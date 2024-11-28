import json
import boto3
import time
import logging
import urllib3

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Boto3 clients
acm_client = boto3.client('acm')
route53_client = boto3.client('route53')

# Initialize the urllib3 PoolManager
http = urllib3.PoolManager()

def send_response(event, context, response_status, response_data, physical_resource_id=None):
    """
    Sends a response to CloudFormation indicating success or failure.
    """

    logger.info(f"In send_response, context.log_stream_name: {context.log_stream_name}")
    logger.info(f"In send_response, physical_resource_id: {physical_resource_id}")

    # Use provided PhysicalResourceId or default to log_stream_name
    physical_resource_id = physical_resource_id or context.log_stream_name

    response_url = event['ResponseURL']
    response_body = {
        'Status': response_status,
        'Reason': f"Details in CloudWatch Log Stream: {context.log_stream_name}",
        'PhysicalResourceId': physical_resource_id,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': response_data
    }

    # Convert the dictionary to JSON
    encoded_body = json.dumps(response_body).encode('utf-8')

    try:
        response = http.request(
            'PUT',
            response_url,
            body=encoded_body, 
            headers={'Content-Type': 'application/json'}
        )

        logger.info(f"Sending to CloudFormation response: {response_status}")

        return response
    
    except Exception as e:
        logger.error(f"Failed to send response to CloudFormation: {str(e)}")

def create_dns_record(hosted_zone_id, record_name, record_value):
    """
    Create or update a DNS validation record in Route 53.
    """
    logger.info(f"Creating DNS record: {record_name} -> {record_value}")
    change_batch = {
        'Changes': [
            {
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'CNAME',
                    'TTL': 60,
                    'ResourceRecords': [{'Value': record_value}]
                }
            }
        ]
    }

    route53_client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch=change_batch
    )
    logger.info("DNS record created or updated successfully.")


def delete_dns_record(hosted_zone_id, record_name, record_value):
    """
    Delete a DNS validation record from Route 53.
    """
    logger.info(f"Deleting DNS record: {record_name}")
    change_batch = {
        'Changes': [
            {
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'CNAME',
                    'TTL': 60,
                    'ResourceRecords': [{'Value': record_value}]
                }
            }
        ]
    }

    route53_client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch=change_batch
    )
    logger.info("DNS record deleted successfully.")


def delete_acm_certificate(certificate_arn):
    """
    Delete the ACM certificate if it exists and is valid.
    """
    logger.info(f"Deleting ACM certificate: {certificate_arn}")
    try:
        acm_client.delete_certificate(CertificateArn=certificate_arn)
        logger.info("ACM certificate deleted successfully.")
    except Exception as e:
        logger.error(f"Error deleting ACM certificate: {str(e)}", exc_info=True)

def wait_and_fetch_cert_resource_record(acm_client, certificate_arn, timeout=300, interval=15):
    """Wait until the ACM certificate includes the ResourceRecord."""
    start_time = time.time()
    while True:
        cert_details = acm_client.describe_certificate(CertificateArn=certificate_arn)
        validation_options = cert_details['Certificate']['DomainValidationOptions'][0]
        
        # Check if the ResourceRecord is available
        if 'ResourceRecord' in validation_options:
            return validation_options['ResourceRecord']
        
        # Check for timeout
        if time.time() - start_time > timeout:
            logger.info("Timeout waiting for ACM certificate ResourceRecord. Will try again")
        
        logger.info(f"Waiting for ResourceRecord. Current status: {validation_options['ValidationStatus']}")
        time.sleep(interval)

def lambda_handler(event, context):
    """
    Lambda function to handle ACM certificate DNS validation via Route 53.
    """
    try:
        # Log the received event for debugging
        logger.info(f"Received event: {json.dumps(event)}")

        # Extract parameters from the event
        props = event.get('ResourceProperties', {})
        domain_name = props.get('DomainName')
        hosted_zone_id = props.get('HostedZoneId')

        # Early fail, if missing properties
        if not all([domain_name, hosted_zone_id]):
            error_message = "Missing one or more required properties."
            logger.error(error_message)
            send_response(
                event, 
                context, 
                response_status = 'FAILED', 
                response_data = {'Message': error_message}
            )
            return {'statusCode': 500, 'body': error_message}
        
        # CREATE/UPDATE share same code, and DELETE has its own block
        logger.info(f"Processing {event['RequestType']} request for domain: {domain_name}")

        if event['RequestType'] in ['Create', 'Update']:
            
            response = acm_client.request_certificate(
                DomainName=domain_name,
                ValidationMethod='DNS',
                SubjectAlternativeNames=[domain_name],
                Options={'CertificateTransparencyLoggingPreference': 'ENABLED'}
            )

            certificate_arn = response['CertificateArn']

            # Check if CertificateArn is available before proceeding with Create or Update actions
            ## We might want to put some re-try mechanism here
            if certificate_arn is None:
                error_message = "CertificateArn is missing, cannot proceed with certificate validation."
                logger.error(error_message)
                send_response(
                    event, 
                    context, 
                    response_status = 'FAILED', 
                    response_data = {'Message': error_message}
                )
                return {'statusCode': 500, 'body': error_message}
            
            logger.info(f"Requested certificate: {certificate_arn}")

            # Re-try mechanism here
            resource_record = wait_and_fetch_cert_resource_record(acm_client, certificate_arn)
            validation_record_name = resource_record['Name']
            validation_record_value = resource_record['Value']

            
            # Create or update the DNS record for DNS validation
            logger.info(f"DNS validation record: {validation_record_name} -> {validation_record_value}")
            create_dns_record(
                hosted_zone_id, validation_record_name, validation_record_value
            )

            # Send response to CloudFormation (Important!!! without it, it'll endlessly wait for the response that we never sent)
            send_response(
                event, 
                context, 
                response_status = 'SUCCESS', 
                response_data = {'Message': 'ACM Certificate created and validated.'},
                physical_resource_id=certificate_arn
            )
            
            return {'statusCode': 200, 'body': json.dumps('Validation record processed successfully.')}
        
        elif event['RequestType'] == 'Delete':

            # Pull all certs, and delete the one that matches the name of this stack's cert.
            domain_name = "static-site.jiwanheo.xyz"  
            all_certs = acm_client.list_certificates(CertificateStatuses=['ISSUED']).get('CertificateSummaryList', [])

            certificate_arn = None
            for cert in all_certs:
                if cert['DomainName'] == domain_name:  # Check if the domain name matches
                    certificate_arn = cert['CertificateArn']
                    break
            
            if certificate_arn is None:
                error_message = "CertificateArn is missing, cannot proceed with certificate validation."
                logger.error(error_message)
                send_response(
                    event, 
                    context, 
                    response_status = 'FAILED', 
                    response_data = {'Message': error_message}
                )
                return {'statusCode': 500, 'body': error_message}
            
            resource_record = wait_and_fetch_cert_resource_record(acm_client, certificate_arn)
            validation_record_name = resource_record['Name']
            validation_record_value = resource_record['Value']

            logger.info(f"Deleting DNS record: {validation_record_name} -> {validation_record_value}")
            delete_dns_record(
                hosted_zone_id, validation_record_name, validation_record_value
            )

            logger.info(f"Deleting certificate: {certificate_arn}")
            delete_acm_certificate(certificate_arn)

            send_response(
                event, 
                context, 
                response_status = 'SUCCESS', 
                response_data = {'Message': "Validation record and certificate deleted successfully."},
                physical_resource_id=certificate_arn
            )

            return {'statusCode': 200, 'body': json.dumps("Validation record and certificate deleted successfully.")}



    except Exception as e:
        logger.error(f"Error processing validation: {str(e)}", exc_info=True)
        send_response(
            event, 
            context, 
            response_status = 'FAILED', 
            response_data = {'Message': f"Error: {str(e)}"}
        )

        return {'statusCode': 500, 'body': json.dumps(f"Error: {str(e)}")}
