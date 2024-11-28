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

def send_response(event, context, response_status, response_data):
    """
    Sends a response to CloudFormation indicating success or failure.
    """
    response_url = event['ResponseURL']
    response_body = {
        'Status': response_status,
        'Reason': response_data,
        'PhysicalResourceId': context.log_stream_name,
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


        if not all([domain_name, hosted_zone_id]):
            error_message = "Missing one or more required properties."
            logger.error(error_message)
            send_response(event, context, 'FAILED', error_message)
            return {'statusCode': 500, 'body': error_message}
        
        if event['RequestType'] in ['Create', 'Update']:
            logger.info(f"Processing {event['RequestType']} request for domain: {domain_name}")
            response = acm_client.request_certificate(
                DomainName=domain_name,
                ValidationMethod='DNS',
                SubjectAlternativeNames=[domain_name],
                Options={'CertificateTransparencyLoggingPreference': 'ENABLED'}
            )

            certificate_arn = response['CertificateArn']

            # Check if CertificateArn is available before proceeding with Create or Update actions
            if certificate_arn is None:
                error_message = "CertificateArn is missing, cannot proceed with certificate validation."
                logger.error(error_message)
                send_response(event, context, 'FAILED', error_message)
                return {'statusCode': 500, 'body': error_message}
            
            logger.info(f"Requested certificate: {certificate_arn}")

            cert_details = acm_client.describe_certificate(CertificateArn=certificate_arn)

            validation_options = cert_details['Certificate']['DomainValidationOptions'][0]

            logger.info(f"Here's validation_options: {validation_options}")

            validation_record_name = validation_options['ResourceRecord']['Name']
            validation_record_value = validation_options['ResourceRecord']['Value']

            logger.info(f"DNS validation record: {validation_record_name} -> {validation_record_value}")

            # Create or update the DNS record for DNS validation
            create_dns_record(
                hosted_zone_id, validation_record_name, validation_record_value
            )

            send_response(event, context, 'SUCCESS', "Validation record processed successfully.")
            return {'statusCode': 200, 'body': json.dumps('Validation record processed successfully.')}
        
        elif event['RequestType'] == 'Delete':
            logger.info(f"Deleting validation record for domain: {domain_name}")

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
                send_response(event, context, 'FAILED', error_message)
                return {'statusCode': 500, 'body': error_message}
            
            cert_details = acm_client.describe_certificate(CertificateArn=certificate_arn)

            validation_options = cert_details['Certificate']['DomainValidationOptions'][0]
            validation_record_name = validation_options['ResourceRecord']['Name']
            validation_record_value = validation_options['ResourceRecord']['Value']

            logger.info(f"Deleting DNS record: {validation_record_name} -> {validation_record_value}")
            delete_dns_record(
                hosted_zone_id, validation_record_name, validation_record_value
            )

            logger.info(f"Deleting certificate: {certificate_arn}")
            delete_acm_certificate(certificate_arn)
        
            send_response(event, context, 'SUCCESS', "Validation record and certificate deleted successfully.")
            return {'statusCode': 200, 'body': json.dumps("Validation record and certificate deleted successfully.")}



    except Exception as e:
        logger.error(f"Error processing validation: {str(e)}", exc_info=True)
        send_response(event, context, 'FAILED', f"Error: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps(f"Error: {str(e)}")}
