#!/bin/bash

sleep 10
if [ -z "${PROXY_HOST_TARGET:-}" ] && [ -z "${SSM_ROUTES_PATH:-}" ]; then
  # Local development only: neither routing mode nor legacy mode is configured,
  # so resolve the API Gateway URL from a local LocalStack instance.
  API_NAME="${API_NAME:-OPDA Facade API}"
  REGION="${REGION:-us-east-1}"
  EDGE="${EDGE:-http://localstack:4566}"

  API_ID=$(aws --endpoint-url "$EDGE" --region "$REGION" apigateway get-rest-apis \
    --query "items[?name=='$API_NAME'].id" --output text)

  export PROXY_HOST_TARGET="http://localstack:4566/_aws/execute-api/${API_ID}/v1"
  echo "Resolved PROXY_HOST_TARGET=${PROXY_HOST_TARGET}"
fi

exec "$@"
