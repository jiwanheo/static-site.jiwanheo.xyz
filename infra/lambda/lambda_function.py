import json
import boto3
import time

acm_client = boto3.client('acm')
route53_client = boto3.client('route53')

def lambda_handler(event, context):
    try:
        # Print event for debugging
        print(f"Received event: {json.dumps(event)}")

        # Extract relevant information from the event
        certificate_arn = event['ResourceProperties']['CertificateArn']
        hosted_zone_id = event['ResourceProperties']['HostedZoneId']
        domain_name = event['ResourceProperties']['DomainName']
        validation_record_name = event['ResourceProperties']['ValidationRecordName']
        validation_record_value = event['ResourceProperties']['ValidationRecordValue']
        
        # Request certificate validation
        if event['RequestType'] == 'Create' or event['RequestType'] == 'Update':
            print(f"Creating validation record for {domain_name} in Route 53...")
            
            # Create the DNS validation record
            change_batch = {
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': validation_record_name,
                            'Type': 'CNAME',
                            'TTL': 60,
                            'ResourceRecords': [{'Value': validation_record_value}]
                        }
                    }
                ]
            }

            # Wait for the ACM certificate to be validated
            print(f"Waiting for validation of ACM certificate {certificate_arn}...")
            wait_for_validation(certificate_arn)

        elif event['RequestType'] == 'Delete':
            print(f"Deleting validation record for {domain_name}...")
            # Delete the DNS validation record
            change_batch = {
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': {
                            'Name': validation_record_name,
                            'Type': 'CNAME',
                            'TTL': 60,
                            'ResourceRecords': [{'Value': validation_record_value}]
                        }
                    }
                ]
            }

        # Execute the change
        route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch=change_batch
        )

        # Return success
        return {'statusCode': 200, 'body': json.dumps('Validation record processed successfully.')}

    except Exception as e:
        print(f"Error: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps(f"Error: {str(e)}")}


def wait_for_validation(certificate_arn):
    """
    Wait for the ACM certificate to be validated.
    """
    while True:
        # Describe the certificate to get its status
        response = acm_client.describe_certificate(CertificateArn=certificate_arn)
        certificate = response['Certificate']
        status = certificate['Status']

        if status == 'ISSUED':
            print("Certificate validation successful.")
            return True
        elif status == 'FAILED':
            raise Exception("Certificate validation failed.")
        
        print("Waiting for certificate validation to complete...")
        time.sleep(30)
