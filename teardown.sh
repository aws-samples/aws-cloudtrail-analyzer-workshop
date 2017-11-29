#!/bin/bash

STACK_NAME=ReInvent2017-SID341
PROFILE=default

while test $# -gt 0; do
  case "$1" in
    -h|--help)
            echo "Tears down the re:Invent 2017 - SID341 CloudFormation stack"
            echo " "
            echo "options:"
            echo "-h, --help                shows this help"
            echo "-p, --profile=PROFILE     specify an AWS CLI profile to use"
            echo "-s, --stack-name=NAME     specify the CloudFormation stack name"
            exit 0
            ;;
    -p)
            shift
            if test $# -gt 0; then
                    export PROFILE=$1
            else
                    echo "no profile specified"
                    exit 1
            fi
            shift
            ;;
    --profile*)
            export PROFILE=`echo $1 | sed -e 's/^[^=]*=//g'`
            shift
            ;;
    -s)
            shift
            if test $# -gt 0; then
                    export STACK_NAME=$1
            else
                    echo "no stack name specified"
                    exit 1
            fi
            shift
            ;;
    --stack-name*)
            export STACK_NAME=`echo $1 | sed -e 's/^[^=]*=//g'`
            shift
            ;;
    *)
            break
            ;;
  esac
done

# Delete the S3 buckets first, otherwise stack deletion will fail
BUCKETS_TO_DELETE=("CloudTrailBucket" "ActivityGenBucket")

for bucket in "${BUCKETS_TO_DELETE[@]}"
do
  actual_bucket_name=$(aws --profile ${PROFILE} cloudformation describe-stack-resource --stack-name ${STACK_NAME} --logical-resource-id ${bucket} | python -c "import sys, json; print json.load(sys.stdin)['StackResourceDetail']['PhysicalResourceId']")
  aws --profile ${PROFILE} s3 rb s3://${actual_bucket_name} --force
done

# Delete the stack and wait for completion
aws --profile ${PROFILE} cloudformation delete-stack --stack-name ${STACK_NAME}

echo "Deleting the CloudFormation stack ${STACK_NAME}"

# This command didn't exist in older versions of the AWS CLI, so ignore any errors
aws --profile ${PROFILE} cloudformation wait stack-delete-complete --stack-name ${STACK_NAME} || true
