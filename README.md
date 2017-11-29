# SID 341: Using AWS CloudTrail Logs for Scalable, Automated Anomaly Detection

In this README you will find instructions and pointers to the resources used for the workshop exercises. In this workshop, there are two exercises:

1. Examining CloudTrail logs
2. Automated detection

After the setup steps below, there are instructions provided for all of the hands-on exercises, clean-up instructions to tear down the CloudFormation stack, and following that a full walkthrough guide on how to complete the exercises.

## What's in here?

This repository contains the following files that will be used for this workshop:

- README.md - This README file
- cloudformation.yaml - The CloudFormation template to deploy the stack of resources
- cloudtrail_analyzer.py - Source code for the Lambda function to analyze CloudTrail logs
  - This code is just for reference since it will also be present in the inline editor in the Lambda console after the CloudFormation stack is deployed
- teardown.sh - Script that deletes the CloudFormation stack
  - Attempting to delete the stack from the console will fail due to the created S3 buckets having contents that need to be deleted first, so this script handles that gracefully

# Initial setup

## Prerequisites

Before getting started, you will need the following:

- AWS account
- Modern, graphical web browser (sorry Lynx users!)
- IAM user with administrator access to the account
- AWS CLI - https://aws.amazon.com/cli/
  - Only needed for the `teardown.sh` script

## Deploying the template

The CloudFormation template creates 2 sets of resources for the following purposes:

1. Analysis of CloudTrail logs using an AWS Lambda function
2. Activity generation to produce CloudTrail logs for analysis

First, log in to your AWS account using the IAM user with administrator access.

For this workshop, we will be working within the Canada Central (ca-central-1) region. To switch regions, click the region dropdown in the top right of the window and select **Canada (Central)**.

To easily deploy the CloudFormation stack using a copy of the *cloudformation.yaml* template that is contained in an S3 bucket, please browse to the following stack launch URL:

http://amzn.to/sid341cfn

1. On the **Select Template** page, note that the template location where it says "Specify an Amazon S3 template URL" is prepopulated with the S3 URL to the template. Click **Next**.
2. On the **Specify Details** page, note that the stack name is prepopulated as "ReInvent2017-SID341", but you may change it if desired. If you'd like to receive alarm notifications via email later when we add support for alarming on CloudTrail-based detections, please fill in the **NotificationEmailAddress** parameter with your email address. Please note that if specifying a notification email address, you will receive a subscription confirmation email shortly after the stack creation completes in which you must click a link to confirm the subscription. Click **Next**.
3. On the **Options** screen, click **Next**.
4. On the Review page, review and confirm the settings. Be sure to check the box acknowledging that the template will create resources.
5. Click  **Create** to deploy the stack. You can view the status of the stack in the AWS CloudFormation console in the **Status** column. You should see a status of **CREATE_COMPLETE** in roughly five minutes

# Exercise 1: Examining CloudTrail logs

In this exercise, you will examine CloudTrail logs in your account, which will include generated activity from the CloudFormation stack you deployed earlier. The goal of this exercise is to familiarize with the structure of the CloudTrail logs, their format, and content.

1. Go to the CloudTrail console, then click on **Event history** on the left menu.
2. Click to expand several different types of events and observe the information presented.
3. With several different events, click the **View event** button while they are expanded to view their raw JSON records. Note the `userIdentity` block, along with some of the more interesting fields like `sourceIPAddress`, `eventSource`, and `eventName`. Depending on the event, you may also see some `requestParameters` and `responseElements` present.

# Exercise 2: Automated detection

In this exercise, you will build a simple CloudTrail log analyzer and detection engine using a Python-based AWS Lambda function.

Some core functionality of the Lambda function has already been provided for you and takes care of the following:

- Receiving and handling incoming notification messages when a new CloudTrail log file gets created in the S3 bucket (the `handler` entry point function)
- Fetching, gunzipping, and loading each CloudTrail log file, and converting the JSON to a Python dictionary that allows straightforward referencing of fields in the event records (the `get_log_file_location` and `get_records` functions).
- Iterating over all of the records in each log file and passing each record to analysis functions (`for` loops in the `handler` that pass individual records to each analysis function in the `analysis_functions` list).

## Getting started

Here are steps you can follow to begin the exercise:

1. Browse to the AWS Lambda console, double checking that you are in region **Canada (Central)**, or **ca-central-1** as shown in the URL.
2. Click on the function whose name begins with "ReInvent2017-SID341-AnalysisLambdaFunc". This is the CloudTrail Analysis Lambda function.
3. You should be on the **Configuration** tab. Scroll down and under **Function code** you will see the code for the Lambda function in the inline, browser-based editor. Skim through the code to become familiar with what it does and how it is structured. The code has copious comments that will help guide you through what each part does.
4. Whenever you make a code change to the Lambda function, you will need to click the **Save** button at the top (just **Save**, *not* **Save and test**) to save your changes before they will take effect. The new code will then be in effect on the next invocation (i.e., when the next CloudTrail log file gets created).

Look at each of the functions contained in the `analysis_functions` tuple. Each of these functions gets passed every CloudTrail record.

The `print_short_record` analysis function is already defined. All it does is print out a shortened form of each CloudTrail record by reading certain fields in the CloudTrail record. Observe how these fields are accessed since you will need to do something similar in the other analysis functions.

The CloudTrail User Guide has a reference on log events that explains in detail what each of the fields in a CloudTrail record mean. You will likely find this to be helpful as you start to analyze the events:

http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html

To see what the abbreviated CloudTrail records being printed by `print_short_record` look like, go to the **Monitoring** tab for the Lambda function and click on **View logs in CloudWatch**. Once in CloudWatch, click on the Log Stream and you will see the output from every invocation of the Lambda function.

Note that the `sourceIPAddress` value for actions performed by the CloudFormation template is "cloudformation.amazonaws.com". Also, notice that some actions have a region of "us-east-1" rather than "ca-central-1". This is because some services, such as IAM (iam.amazonaws.com), are global services and report region as "us-east-1" (trivia: that was the first AWS region!).

## Phase 1: Deleting logs

The deletion of logs is an action that should normally not occur in most accounts, and may indicate an attacker trying to cover tracks.

In this exercise, we will focus on API calls that delete logs in CloudWatch Logs or CloudTrail. You need to implement code for the `deleting_logs` function to check for those API calls by looking for API events whose name starts with `"Delete"`. Use what you've learned about looking at CloudTrail records so far to identify the fields you will need to use, and borrow code patterns from `print_short_record` as needed.

When a matching record is found, print it out using `print_short_record` and return True.

Curious about what some of the log deletion API calls do? Here are some docs to check out:

- CloudWatch Logs
  - http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteLogGroup.html
  - http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteLogStream.html
- CloudTrail
  - http://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DeleteTrail.html

### Bonus round!

Expand the check to look for an API call that stops logging on a trail in CloudTrail (without deleting the trail).

## Phase 2: Off-instance usage of instance credentials

The usage of session credentials from a running EC2 instance from outside of that instance is a potential indicator that an attacker may have obtained leaked or stolen credentials.

Implement code for the `instance_creds_used_outside_ec2` function to check for API calls made using EC2 instance credentials "off-instance", or in other words, credentails that have been removed from the instance and are being used outside of it.

Examine each record to look for ones that satisfy the following 3 properties for API calls made using instance credentials:

1. User making the call is using an assumed role
2. The user's access key is a session key that begins with the string `'AS'` instead of `'AK'`
3. The user's ARN ends with an instance identifier consisting of the string 'i-' followed by 8 or more alphanumeric characters in the username portion (e.g., i-d34db33f)

For #3, a regular expression pattern called `instance_identifier_arn_pattern` has been predefined for you to use. You can use it with Python's `match` function that returns True if the pattern matches and False otherwise:

```python
arn_matches = instance_identifier_arn_pattern.match(arn)
if arn_matches:
    print('ARN appears to contain an instance identifier!')
```
        
When a matching record is found, print it out using `print_short_record` and return True.

Curious about what instance credentials are? See this documentation for more: 

http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials

## Phase 3: Sending metrics to CloudWatch to trigger an alarm

The CloudFormation template created a CloudWatch alarm with the following properties:

- ComparisonOperator: GreaterThanOrEqualToThreshold
- EvaluationPeriods: 1
- MetricName: "AnomaliesDetected"
- Namespace: "AWS/reInvent2017/SID341"
- Period: 60
- Statistic: "Sum"
- Threshold: 1.0

This means that if you put metric data to CloudWatch using MetricName `AnomaliesDetected`,  Namespace `AWS/reInvent2017/SID341`, and a Value of `1`, the CloudWatch alarm will fire by going into `ALARM` state.

There is a pre-defined CloudWatch Boto client in the `handler` that you can use for this:

```python
cloudwatch = session.client('cloudwatch')
```

When the CloudWatch alarm fires, if you had set up the `NotificationEmailAddress` parameter earlier when creating the CloudFormation stack, you will receive an email about the alarm firing. You can also browse to the CloudWatch console and click on **Alarms** in the left menu to view the alarm and its current state.

### Extra credit: Alarming improvements
        
These metrics, and the accompanying alarm, are quite simple, but it is straightforward to adjust this to have, for instance, separate alarms for each analysis function, or set different triggering conditions for the alarm. You could have separate alarms for each analysis function by changing the `MetricName` accordingly, and updating the `cloudformation.yaml` template to create alarms for each metric.

For more information, please visit the following CloudWatch User Guide pages:

- Creating Alarms: http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
- Using Metrics: http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/working_with_metrics.html
- Metrics and Dimensions Reference: http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CW_Support_For_AWS.html

# Cleaning up

To delete the CloudFormation stack, a shell script, `teardown.sh`, has been provided. Run as follows:

```./teardown.sh```

- *Q: The script is not running.*
- A: It may need to be made executable. Do `chmod +x teardown.sh` to fix this.

- *Q: I'm using a different AWS CLI profile than the default.*
- A: The script supports a flag to specify a CLI profile that is configured in your `~/.aws/config` file. Do `./teardown.sh -p PROFILE_NAME`.

# Walkthrough guide for Exercise 2: Automated detection 

This walkthrough will give full details on how to complete each phase of the automated detection exercise, including finished code snippets that can be copied and pasted into the Lambda function.

## Phase 1: Deleting logs

To solve this phase, you need to examine each record to look for ones with an `eventSource` of `logs.amazonaws.com` or `cloudtrail.amazonaws.com` and an `eventName` that starts with the string `"Delete"`.

The completed function will look like the following:

```python
def deleting_logs(record):
    """
    Checks for API calls that delete logs in CloudWatch Logs or CloudTrail.

    :return: True if record matches, False otherwise
    """
    event_source = record['eventSource']
    event_name = record['eventName']

    if event_source in ['logs.amazonaws.com', 'cloudtrail.amazonaws.com']: 
        if event_name.startswith('Delete'):
            print_short_record(record)
            return True

    return False
```
        
Once finished, you will also want to comment out or remove `print_short_record` from the `analysis_functions` tuple so that only records that match the check in `deleting_logs` get printed.

### Bonus round

For the bonus round, add the following check to the function:

```python
if event_source == 'cloudtrail.amazonaws.com' and event_name == 'StopLogging':
    print_short_record(record)
    return True
```

## Phase 2: Off-instance usage of instance credentials

To solve this phase, you must implement checks of the 3 properties that were specified:

1. `userIdentity.type` is `AssumedRole`
2. `userIdentity.accessKey` begins with string `'AS'` instead of `'AK'`
3. `userIdentity.arn` matches the `instance_identifier_arn_pattern`

Please note that the check in #3 is imperfect beacuse we don't know whether that is or was a valid instance identifier for an instance in this account (or any account, for that matter), since the username could technically be set to something that looks like an instance identifier, which could lead to a false positive. However, for our purposes in this workshop it will suffice. Improving this check will be left as extra credit for the reader ;)

The completed function will look like the following:

```python
instance_identifier_arn_pattern = re.compile(r'(.*?)/i\-[a-zA-Z0-9]{8,}$')

def instance_creds_used_outside_ec2(record):
    """
    Check for usage of EC2 instance credentials from outside the EC2 service.

    :return: True if record matches, False otherwise
    """
    identity = record['userIdentity']

    # First, check that the role type is assumed role
    role_type = identity.get('type', '')
    if role_type != 'AssumedRole':
        return False

    # Next, check that the AKID starts with 'AS'
    access_key = identity.get('accessKeyId', '')
    if not access_key.startswith('AS'):
        return False

    # Finally, check that the end of the user ARN is an instance identifier
    arn = identity.get('arn', '')
    if instance_identifier_arn_pattern.match(arn):
        print_short_record(record)
        return True

    return False
```
        
## Phase 3: Sending metrics to CloudWatch to trigger an alarm

You can use the following code snippet at the end of your Lambda function handler, inside the `for` loop that iterates over each record:

```python
if func(record):
    cloudwatch.put_metric_data(
        Namespace='AWS/reInvent2017/SID341',
        MetricData=[{
            'MetricName': 'AnomaliesDetected',
            'Value': 1,
            'Unit': 'Count',
        }]
    )
```
        
It uses the pre-defined CloudWatch Boto client to put metric data to CloudWatch for a specific metric that the CloudWatch alarm is monitoring.
