#!/bin/bash

# Check if two input parameters were provided
if [ $# -ne 4 ]; then
    echo "Invalid input. Usage: ./setSamsungTvConf.sh <backlight> <brightness> <contrast> <color_temperature>"
    exit 1
fi

# Store the input parameters in variables
backlight=$1
brightness=$2
contrast=$3
color_temperature=$4

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
curl -k -X POST https://IP_ADDRESS:4000/api/v1/devices/settings/set \
    -H "Content-Type: application/json" \
    -H "Authorization: $access_token" \
    -d "{\"devices\":[{\"mac\":\"1c-af-4a-50-af-36\"}],\"settings\":{\"display_conf\":{\"maintenance\":{\"format\":\"${backlight}\"},\"picture_video\":{\"brightness\":\"${brightness}\",\"contrast\":\"${contrast}\",\"color_temperature\":\"${color_temperature}K\"}}}}"
