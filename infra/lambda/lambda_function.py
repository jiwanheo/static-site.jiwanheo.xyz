import json
import boto3
import time
import logging
import requests


# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Boto3 clients
acm_client = boto3.client('acm')
route53_client = boto3.client('route53')

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

    logger.info(f"Sending response to CloudFormation: {response_body}")

    try:
        response = requests.put(response_url, json=response_body)
        logger.info(f"Response sent to CloudFormation: {response.status_code}")
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


def wait_for_validation(certificate_arn):
    """
    Wait for the ACM certificate to be validated.
    """
    while True:
        response = acm_client.describe_certificate(CertificateArn=certificate_arn)
        certificate = response.get('Certificate', {})
        status = certificate.get('Status', 'PENDING_VALIDATION')

        if status == 'ISSUED':
            logger.info("Certificate validation successful.")
            return True
        elif status == 'FAILED':
            logger.error("Certificate validation failed.")
            raise Exception("Certificate validation failed.")
        
        logger.info("Waiting for certificate validation to complete...")
        time.sleep(30)


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
        certificate_arn = event.get('ResourceProperties', {}).get('CertificateArn', None)
        hosted_zone_id = props.get('HostedZoneId')
        domain_name = props.get('DomainName')
        validation_record_name = props.get('ValidationRecordName')
        validation_record_value = props.get('ValidationRecordValue')

        if not all([hosted_zone_id, domain_name, validation_record_name, validation_record_value]):
            error_message = "Missing one or more required properties."
            logger.error(error_message)
            send_response(event, context, 'FAILED', error_message)
            return {'statusCode': 500, 'body': error_message}
        
        # Check if CertificateArn is available before proceeding with Create or Update actions
        if certificate_arn is None and event['RequestType'] in ['Create', 'Update']:
            error_message = "CertificateArn is missing, cannot proceed with certificate validation."
            logger.error(error_message)
            send_response(event, context, 'FAILED', error_message)
            return {'statusCode': 500, 'body': error_message}
        
        if event['RequestType'] in ['Create', 'Update']:
            logger.info(f"Processing {event['RequestType']} request for domain: {domain_name}")

            # Create or update the DNS validation record
            create_dns_record(
                hosted_zone_id, validation_record_name, validation_record_value
            )

            # Wait for ACM certificate validation if certificate_arn exists
            if certificate_arn:
                logger.info(f"Waiting for ACM certificate validation: {certificate_arn}")
                wait_for_validation(certificate_arn)
        
        elif event['RequestType'] == 'Delete':
            logger.info(f"Deleting validation record for domain: {domain_name}")

            # Delete the DNS validation record
            delete_dns_record(
                hosted_zone_id, validation_record_name, validation_record_value
            )

            # If certificate_arn is available, we can proceed with certificate deletion
            if certificate_arn:
                delete_acm_certificate(certificate_arn)

        logger.info("Successfully processed validation record.")
        send_response(event, context, 'SUCCESS', "Validation record processed successfully.")
        return {'statusCode': 200, 'body': json.dumps('Validation record processed successfully.')}

    except Exception as e:
        logger.error(f"Error processing validation: {str(e)}", exc_info=True)
        send_response(event, context, 'FAILED', f"Error: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps(f"Error: {str(e)}")}
