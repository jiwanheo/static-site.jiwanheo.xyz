#!/bin/bash

# Define the domain name for the certificate
DOMAIN_NAME="static-site.jiwanheo.xyz"

# Fetch the ACM certificate ARN using AWS CLI
CERT_ARN=$(aws acm list-certificates --query "CertificateSummaryList[?DomainName=='$DOMAIN_NAME'].CertificateArn" --output text)

# Ensure the ARN was retrieved
if [ "$CERT_ARN" == "None" ]; then
  echo "Certificate not found for domain: $DOMAIN_NAME"
  exit 1
fi

echo "Certificate ARN: $CERT_ARN"

# Poll until the certificate is issued (status: 'ISSUED')
echo "Waiting for certificate validation to complete..."

START_TIME=$(date +%s)  # Capture the start time
TIMEOUT=900  # Timeout after 15 minutes (900 seconds)

while true; do
  # Get the current status of the certificate
  CERT_STATUS=$(aws acm describe-certificate --certificate-arn $CERT_ARN --query "Certificate.Status" --output text)

  echo "Certificate status: $CERT_STATUS"

  if [ "$CERT_STATUS" == "ISSUED" ]; then
    echo "Certificate validation completed successfully!"
    break
  fi

  # Check if timeout has been reached
  CURRENT_TIME=$(date +%s)
  ELAPSED_TIME=$((CURRENT_TIME - START_TIME))

  if [ "$ELAPSED_TIME" -gt "$TIMEOUT" ]; then
    echo "Timeout reached. Certificate validation did not complete in time."
    exit 1  # Fail the job if timeout is reached
  fi

  # Wait before checking again
  sleep 30  # Wait 30 seconds before checking again
done
