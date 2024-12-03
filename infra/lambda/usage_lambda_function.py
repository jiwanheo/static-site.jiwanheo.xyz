import boto3
import json
import logging

# Create CloudFront client
cloudfront = boto3.client('cloudfront')

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):

    logger.info(f"Here's the event: {event}")

    # Extract the SNS message
    sns_message = event['Records'][0]['Sns']['Message']

    # Parse the SNS message (which is JSON inside a string)
    alarm_details = json.loads(sns_message)

    # Extract details
    alarm_state = alarm_details['NewStateValue']

    # Extract CloudFront DistributionId from Dimensions
    trigger_details = alarm_details.get('Trigger', {})
    dimensions = trigger_details.get('Dimensions', [])
    distribution_id = None

    for dimension in dimensions:
        if dimension['name'] == 'DistributionId':
            distribution_id = dimension['value']
            break

    # Initialize CloudFront client
    client = boto3.client('cloudfront')

    try:
        # Get the current distribution configuration
        response = client.get_distribution_config(Id=distribution_id)
        config = response['DistributionConfig']
        etag = response['ETag']

        # Check current state and update 'Enabled' field based on alarm state
        if alarm_state == "ALARM":
            config['Enabled'] = False  # Disable the distribution
            action = "disable"
        elif alarm_state == "OK":
            config['Enabled'] = True   # Enable the distribution
            action = "enable"
        else:
            return {
                "statusCode": 200,
                "body": f"No action needed for state: {alarm_state}"
            }

        # Update the distribution configuration
        update_response = client.update_distribution(
            Id=distribution_id,
            IfMatch=etag,
            DistributionConfig=config
        )

        return {
            "statusCode": 200,
            "body": f"CloudFront distribution {distribution_id} successfully {action}d."
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": f"Error updating CloudFront distribution: {str(e)}"
        }