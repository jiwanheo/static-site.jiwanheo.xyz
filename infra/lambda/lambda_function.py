import json

def lambda_handler(event, context):
    print("Lambda function invoked successfully!")

    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
