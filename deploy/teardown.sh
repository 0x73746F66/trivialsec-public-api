#!/bin/bash -x

if [[ $EUID -eq 0 ]]; then
   echo -e "This script must not be run as root" 
   exit 1
fi
if [[ ! -d src ]]; then
    echo -e "Run this from the project root directory"
    exit 1
fi
if [[ -f .env ]]; then
    source .env
fi
if [[ -z "${APP_NAME}" ]]; then
    APP_NAME=appserver
fi
readonly instanceId="$(aws ec2 describe-instances --filters 'Name=tag:Name,Values=Baker-${APP_NAME}' --query 'Reservations[].Instances[].InstanceId' --output text)"
if [[ ${instanceId} != i-* ]]; then
    echo No baker instances to terminate
    exit 0
fi
aws ec2 terminate-instances --instance-ids ${instanceId}

exit 0