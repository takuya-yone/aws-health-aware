import json
import boto3
import os
import re
import time
import decimal
import socket
import configparser
import difflib
from dateutil import parser
from datetime import datetime, timedelta
from urllib.parse import urlencode
from urllib.request import Request, urlopen, URLError, HTTPError
from botocore.config import Config
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
import difflib
from pprint import pformat

def to_string_lines(obj):
    # dictのオブジェクトを文字列に変換＆改行で分割したリストを返却
    return pformat(obj,width=1000).split('\n')

def get_secrets():
    secret_teams_name = "MicrosoftChannelID"
    secret_slack_name = "SlackChannelID"
    secret_chime_name = "ChimeChannelID"
    region_name = os.environ['AWS_REGION']
    get_secret_value_response_assumerole = ""
    get_secret_value_response_eventbus = ""
    get_secret_value_response_chime = ""
    get_secret_value_response_teams = ""
    get_secret_value_response_slack = ""
    event_bus_name = "EventBusName"
    secret_assumerole_name = "AssumeRoleArn"

    # create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    # Iteration through the configured AWS Secrets
    try:
        get_secret_value_response_teams = client.get_secret_value(
            SecretId=secret_teams_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print("No AWS Secret configured for Teams, skipping")
            teams_channel_id = "None"
        else:
            print("There was an error with the Teams secret: ", e.response)
            teams_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_teams:
            teams_channel_id = get_secret_value_response_teams['SecretString']
        else:
            teams_channel_id = "None"
    try:
        get_secret_value_response_slack = client.get_secret_value(
            SecretId=secret_slack_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print("No AWS Secret configured for Slack, skipping")
            slack_channel_id = "None"
        else:
            print("There was an error with the Slack secret: ", e.response)
            slack_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_slack:
            slack_channel_id = get_secret_value_response_slack['SecretString']
        else:
            slack_channel_id = "None"
    try:
        get_secret_value_response_chime = client.get_secret_value(
            SecretId=secret_chime_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print("No AWS Secret configured for Chime, skipping")
            chime_channel_id = "None"
        else:
            print("There was an error with the Chime secret: ", e.response)
            chime_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_chime:
            chime_channel_id = get_secret_value_response_chime['SecretString']
        else:
            chime_channel_id = "None"
    try:
        get_secret_value_response_assumerole = client.get_secret_value(
            SecretId=secret_assumerole_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print("No AWS Secret configured for Assume Role, skipping")
            assumerole_channel_id = "None"
        else:
            print("There was an error with the Assume Role secret: ", e.response)
            assumerole_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_assumerole:
            assumerole_channel_id = get_secret_value_response_assumerole['SecretString']
        else:
            assumerole_channel_id = "None"
    try:
        get_secret_value_response_eventbus = client.get_secret_value(
            SecretId=event_bus_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print("No AWS Secret configured for EventBridge, skipping")
            eventbus_channel_id = "None"
        else:
            print("There was an error with the EventBridge secret: ", e.response)
            eventbus_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_eventbus:
            eventbus_channel_id = get_secret_value_response_eventbus['SecretString']
        else:
            eventbus_channel_id = "None"
        secrets = {
            "teams": teams_channel_id,
            "slack": slack_channel_id,
            "chime": chime_channel_id,
            "eventbusname": eventbus_channel_id,
            "ahaassumerole": assumerole_channel_id
        }
        # uncomment below to verify secrets values
        #print("Secrets: ",secrets)
    return secrets


def get_last_aws_update(event_details):
    """
    Takes as input the event_details and returns the last update from AWS (instead of the entire timeline)

    :param event_details: Detailed information about a specific AWS health event.
    :type event_details: dict
    :return: the last update message from AWS
    :rtype: str
    """
    aws_message = event_details['successfulSet'][0]['eventDescription']['latestDescription']
    return aws_message


def cleanup_time(event_time):
    """
    Takes as input a datetime string as received from The AWS Health event_detail call.  It converts this string to a
    datetime object, changes the timezone to EST and then formats it into a readable string to display in Slack.

    :param event_time: datetime string
    :type event_time: str
    :return: A formatted string that includes the month, date, year and 12-hour time.
    :rtype: str
    """
    event_time = datetime.strptime(event_time[:16], '%Y-%m-%d %H:%M')
    return event_time.strftime("%Y-%m-%d %H:%M:%S")


def send_to_slack(message, webhookurl):
    slack_message = message
    req = Request(webhookurl, data=json.dumps(slack_message).encode("utf-8"),
                  headers={'content-type': 'application/json'})
    print('------------send message!------------')
    try:
        response = urlopen(req)
        response.read()
    except HTTPError as e:
        print("Request failed : ", e.code, e.reason)
    except URLError as e:
        print("Server connection failed: ", e.reason, e.reason)


def generate_message(
        affectedAccountIDs,
        affectedOrgEntities,
        service,
        region,
        statusCode,
        arn,
        latestDescription_ja,
        latestDescription_en):
    # https://app.slack.com/block-kit-builder/
    message = ""
    summary = ""

    summary += (
        f":heavy_check_mark:*[RESOLVED] The AWS Health issue with the {service.upper()} service in "
        f"the {region.upper()} region is now resolved.*")
    message = {
        # "blocks": [
        #     {
        #         "type": "divider"
        #     },
        # ],
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": summary
                }
            },
            # {
            # 	"type": "section",
            # 	"text": {
            # 		"type": "mrkdwn",
            # 		"text": "This is"
            # 	},
            # 	"accessory": {
            # 		"type": "overflow",
            # 		"options": [
            # 			{
            # 				"text": {
            # 					"type": "plain_text",
            # 					"text": 'サンプル',
            # 					"emoji": True
            # 				},
            # 			}
            # 		],
            # 	}
            # },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "チケット起票",
                            "emoji": True
                        },
                        "value": "click_me_123",
                        "url": "https://google.com"
                    }
                ]
            },

        ],
        "attachments": [
            {
                "color": "00ff00",
                "fields": [
                    {"title": "Account(s)",
                     "value": affectedAccountIDs,
                     "short": True},
                    {"title": "Resource(s)",
                     "value": affectedOrgEntities,
                     "short": True},
                    {"title": "Service", "value": service, "short": True},
                    {"title": "Region", "value": region, "short": True},
                    # { "title": "Start Time (UTC)", "value": cleanup_time(event_details['successfulSet'][0]['event']['startTime']), "short": True },
                    # { "title": "End Time (UTC)", "value": cleanup_time(event_details['successfulSet'][0]['event']['endTime']), "short": True },
                    {"title": "Status", "value": statusCode, "short": True},
                    {"title": "Event ARN", "value": arn, "short": False},
                ],
            },
            {
                "color": "00ff00",
                "fields": [
                    {"title": "Updates(JA)",
                     "value": latestDescription_ja,
                     "short": False},
                ],
            },

            {
                "color": "00ff00",
                "fields": [
                    {"title": "Updates(EN)",
                     "value": latestDescription_en,
                     "short": False}
                ],
            },




        ]

    }

    return message



def generate_diff_message(
        affectedAccountIDs,
        affectedOrgEntities,
        service,
        region,
        statusCode,
        arn,
        latestDescription_ja,
        latestDescription_en,
        diff_text):
    # https://app.slack.com/block-kit-builder/
    message = ""
    summary = ""

    summary += (
        f":heavy_check_mark:*[RESOLVED] The AWS Health issue with the {service.upper()} service in "
        f"the {region.upper()} region is now resolved.*")
    message = {
        # "blocks": [
        #     {
        #         "type": "divider"
        #     },
        # ],
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": summary
                }
            },
            # {
            # 	"type": "section",
            # 	"text": {
            # 		"type": "mrkdwn",
            # 		"text": "This is"
            # 	},
            # 	"accessory": {
            # 		"type": "overflow",
            # 		"options": [
            # 			{
            # 				"text": {
            # 					"type": "plain_text",
            # 					"text": 'サンプル',
            # 					"emoji": True
            # 				},
            # 			}
            # 		],
            # 	}
            # },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "チケット起票",
                            "emoji": True
                        },
                        "value": "click_me_123",
                        "url": "https://google.com"
                    }
                ]
            },

        ],
        "attachments": [
            {
                "color": "00ff00",
                "fields": [
                    {"title": "Account(s)",
                     "value": affectedAccountIDs,
                     "short": True},
                    {"title": "Resource(s)",
                     "value": affectedOrgEntities,
                     "short": True},
                    {"title": "Service", "value": service, "short": True},
                    {"title": "Region", "value": region, "short": True},
                    # { "title": "Start Time (UTC)", "value": cleanup_time(event_details['successfulSet'][0]['event']['startTime']), "short": True },
                    # { "title": "End Time (UTC)", "value": cleanup_time(event_details['successfulSet'][0]['event']['endTime']), "short": True },
                    {"title": "Status", "value": statusCode, "short": True},
                    {"title": "Event ARN", "value": arn, "short": False},
                ],
            },
            {
                "color": "00ff00",
                "fields": [
                    {"title": "Diff",
                     "value": diff_text,
                     "short": False},
                ],
            },




        ]

    }

    return message

def lambda_handler(event, context):
    # TODO implement
    print(json.dumps(event))
    eventName = event['Records'][0]['eventName']
    print(eventName)
    secrets = get_secrets()
    slack_message = ''

    if eventName == 'INSERT':
        new_event_record = event['Records'][0]['dynamodb']['NewImage']

        arn = new_event_record['arn']['S']
        statusCode = new_event_record['statusCode']['S']
        affectedAccountIDs = new_event_record['affectedAccountIDs']['L']
        affectedOrgEntities = new_event_record['affectedOrgEntities']['L']
        latestDescription_en = new_event_record['latestDescription']['S']
        latestDescription_ja = ''
        service = new_event_record['service']['S']
        region = new_event_record['region']['S']



        _event_latestDescription_split = latestDescription_en.split('\n\n')
        _event_latestDescription_ja_list = []
        translate_client = boto3.client('translate')
        for text in _event_latestDescription_split:
            response = translate_client.translate_text(
                Text=text,
                SourceLanguageCode='en',
                TargetLanguageCode='ja'
            )
            _event_latestDescription_ja_list.append(response.get('TranslatedText'))
        latestDescription_ja = '\n\n'.join(_event_latestDescription_ja_list)

        slack_message = generate_message(
            affectedAccountIDs,
            affectedOrgEntities,
            service,
            region,
            statusCode,
            arn,
            latestDescription_ja,
            latestDescription_en)
        # print(slack_message)

        send_to_slack(slack_message, secrets['slack'])


    if eventName == 'MODIFY':
        new_event_record = event['Records'][0]['dynamodb']['NewImage']
        old_event_record = event['Records'][0]['dynamodb']['OldImage']

        # print(new_event_record['latestDescription(JA)']['S'])
        arn = new_event_record['arn']['S']
        statusCode = new_event_record['statusCode']['S']
        affectedAccountIDs = new_event_record['affectedAccountIDs']['L']
        affectedOrgEntities = new_event_record['affectedOrgEntities']['L']
        latestDescription_en = new_event_record['latestDescription']['S']
        service = new_event_record['service']['S']
        region = new_event_record['region']['S']
        latestDescription_ja = ''

        _event_latestDescription_split = latestDescription_en.split('\n\n')
        _event_latestDescription_ja_list = []
        translate_client = boto3.client('translate')
        for text in _event_latestDescription_split:
            response = translate_client.translate_text(
                Text=text,
                SourceLanguageCode='en',
                TargetLanguageCode='ja'
            )
            _event_latestDescription_ja_list.append(response.get('TranslatedText'))
        latestDescription_ja = '\n\n'.join(_event_latestDescription_ja_list)


        diff_text = ''
        diff = difflib.Differ()
        print(old_event_record)
        print(new_event_record)
        output_diff = diff.compare(old_event_record,new_event_record)
        print(output_diff)



        # new_event_record_lines = to_string_lines(new_event_record['latestDescription']['S'])
        # old_event_record_lines = to_string_lines(old_event_record['latestDescription']['S'])

        # output_diff = diff.compare(new_event_record_lines,old_event_record_lines)
        # diff_text = ''
        # for data in output_diff:
        #     if data[0:1] in ['+', '-']:
        #         # print(data)
        #         diff_text += data
        # print(diff_text)

        slack_message = generate_diff_message(
            affectedAccountIDs,
            affectedOrgEntities,
            service,
            region,
            statusCode,
            arn,
            latestDescription_ja,
            latestDescription_en,
            diff_text)
        print(slack_message)

        # slack_message = generate_message(
        #     affectedAccountIDs,
        #     affectedOrgEntities,
        #     service,
        #     region,
        #     statusCode,
        #     arn,
        #     latestDescription_ja,
        #     latestDescription_en)
        # print(slack_message)

        send_to_slack(slack_message, secrets['slack'])

    return {
        'statusCode': 200,
        'body': json.dumps(slack_message)
    }
