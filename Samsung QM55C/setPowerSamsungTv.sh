#!/bin/bash

# Check if two input parameters were provided
if [ $# -ne 1 ]; then
    echo "Invalid input. Usage: ./setPowerSamsungTv.sh <ON/OFF> (capital letters)"
    exit 1
fi

state=$1

# Authenticate and get the access token
access_token=$(curl -k -X POST https://IP_ADDRESS:4000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"id":"admin","password":"PASSWORD"}' | jq -r '.access_token')

# Check if access_token was retrieved
if [ -z "$access_token" ]; then
    echo "Failed to retrieve access token"
    exit 1
fi

# Use the access token to make the API request for both backlight and color temperature
curl -k -X POST https://IP_ADDRESS:4000/api/v1/devices/power \
    -H "Content-Type: application/json" \
    -H "Authorization: $access_token" \
    -d "{\"devices\":[{\"mac\":\"1c-af-4a-50-af-36\"}],\"state\":\"${state}\"}"
