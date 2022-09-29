import json
import boto3
import os
import difflib
from dateutil import parser
from datetime import datetime, timedelta
from urllib.request import Request, urlopen, URLError, HTTPError
from botocore.exceptions import ClientError
import difflib
from pprint import pformat

from aws_lambda_powertools import Logger
from aws_lambda_powertools import Tracer

region_name = os.environ['AWS_REGION']
tracer = Tracer()
logger = Logger()


DYNAMO_ACCOUNT_CONFIG_TABLE_NAME = os.environ['DYNAMO_ACCOUNT_CONFIG_TABLE_NAME']


def to_string_lines(obj):
    # dictのオブジェクトを文字列に変換＆改行で分割したリストを返却
    return pformat(obj, compact=True).split('\n')
    # return plogger.info(obj)


def get_organizations_accounts():
    org_client = boto3.client('organizations')
    response = org_client.list_accounts()
    return response


def get_translated_text(text):
    translate_client = boto3.client('translate')
    response = translate_client.translate_text(
        Text=text,
        SourceLanguageCode='en',
        TargetLanguageCode='ja'
    )
    return response.get('TranslatedText')


def get_account_config(accountID):

    dynamodb = boto3.resource('dynamodb')
    account_config_table = dynamodb.Table(DYNAMO_ACCOUNT_CONFIG_TABLE_NAME)
    account_config_table_response = account_config_table.get_item(
        Key={
            'AccountID': str(accountID)
        }
    )
    item = account_config_table_response.get('Item', {})
    return item


def get_discription_diff(new_description, old_description):
    new_description_list = new_description.split('\n\n')
    old_description_list = old_description.split('\n\n')
    diff_list = list(set(new_description_list) - set(old_description_list))
    if len(diff_list) == 0:
        return ''
    else:
        return '\n\n'.join(text for text in diff_list)


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
    secrets_manager_client = boto3.client('secretsmanager')
    # Iteration through the configured AWS Secrets
    try:
        get_secret_value_response_teams = secrets_manager_client.get_secret_value(
            SecretId=secret_teams_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            teams_channel_id = "None"
        else:
            teams_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_teams:
            teams_channel_id = get_secret_value_response_teams['SecretString']
        else:
            teams_channel_id = "None"
    try:
        get_secret_value_response_slack = secrets_manager_client.get_secret_value(
            SecretId=secret_slack_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            slack_channel_id = "None"
        else:
            slack_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_slack:
            slack_channel_id = get_secret_value_response_slack['SecretString']
        else:
            slack_channel_id = "None"
    try:
        get_secret_value_response_chime = secrets_manager_client.get_secret_value(
            SecretId=secret_chime_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            chime_channel_id = "None"
        else:
            chime_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_chime:
            chime_channel_id = get_secret_value_response_chime['SecretString']
        else:
            chime_channel_id = "None"
    try:
        get_secret_value_response_assumerole = secrets_manager_client.get_secret_value(
            SecretId=secret_assumerole_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            assumerole_channel_id = "None"
        else:
            assumerole_channel_id = "None"
    finally:
        if 'SecretString' in get_secret_value_response_assumerole:
            assumerole_channel_id = get_secret_value_response_assumerole['SecretString']
        else:
            assumerole_channel_id = "None"
    try:
        get_secret_value_response_eventbus = secrets_manager_client.get_secret_value(
            SecretId=event_bus_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            eventbus_channel_id = "None"
        else:
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
        #logger.info("Secrets: ",secrets)
    return secrets


def send_slack(message, webhookurl):
    slack_message = message
    req = Request(webhookurl, data=json.dumps(slack_message).encode("utf-8"),
                  headers={'content-type': 'application/json'})
    print('------------send Slack message!------------')
    try:
        response = urlopen(req)
        print("Request success : ", response.read())
    except HTTPError as e:
        print("Request failed : ", e.code, e.reason)
    except URLError as e:
        print("Server connection failed: ", e.reason, e.reason)

def send_email(message, recipient_list):
    # SENDER = os.environ['FROM_EMAIL']
    SENDER = "t-yonezawa@nri.co.jp"
    #AWS_REGIONS = "us-east-1"
    AWS_REGION = os.environ['AWS_REGION']
    subject = "AWS Health Alert"
    client = boto3.client('ses', region_name=AWS_REGION)
    print('------------send Email message!------------')
    response = client.send_email(
        Source=SENDER,
        Destination={
            'ToAddresses': recipient_list
        },
        Message={
            'Body': {
                'Html': {
                    'Data': message
                },
            },
            'Subject': {
                'Charset': 'UTF-8',
                'Data': subject,
            },
        },
    )
    logger.info(response)

def generate_insert_slack_message(
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

    if len(affectedAccountIDs) >= 1:
        _tmpList = list(map(lambda x: x['S'], affectedAccountIDs))
        _affectedAccountIDs = "\n".join(_tmpList)
    else:
        _affectedAccountIDs = "All accounts in region"
    if len(affectedOrgEntities) >= 1:
        _tmpList = list(map(lambda x: x['S'], affectedOrgEntities))
        _affectedOrgEntities = "\n".join(_tmpList)
    else:
        _affectedOrgEntities = "All resources in region"

    summary += (
        f":collision:*[NEW] AWS Health reported an issue with the {service.upper()} service in "
        f"the {region.upper()} region.*")
    message = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": summary
                }
            },
        ],
        "attachments": [
            {
                "color": "00ff00",
                "fields": [
                    {"title": "Account(s)",
                     "value": _affectedAccountIDs,
                     "short": True},
                    {"title": "Resource(s)",
                     "value": _affectedOrgEntities,
                     "short": True},
                    {"title": "Service", "value": service, "short": True},
                    {"title": "Region", "value": region, "short": True},
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


def generate_modify_slack_message(
        affectedAccountIDs,
        affectedOrgEntities,
        service,
        region,
        statusCode,
        arn,
        latestDescription_ja,
        latestDescription_en,
        description_diff_text_ja,
        description_diff_text_en):
    # https://app.slack.com/block-kit-builder/
    message = ""
    summary = ""
    logger.info(affectedAccountIDs)
    logger.info(affectedOrgEntities)

    if len(affectedAccountIDs) >= 1:
        _tmpList = list(map(lambda x: x['S'], affectedAccountIDs))
        _affectedAccountIDs = "\n".join(_tmpList)
    else:
        _affectedAccountIDs = "All accounts in region"
    if len(affectedOrgEntities) >= 1:
        _tmpList = list(map(lambda x: x['S'], affectedOrgEntities))
        _affectedOrgEntities = "\n".join(_tmpList)
    else:
        _affectedOrgEntities = "All resources in region"

    if statusCode == "closed":
        summary += (
            f":white_check_mark:*[RESOLVED] The AWS Health issue with the {service.upper()} service in "
            f"the {region.upper()} region is now resolved.*")
        color = "00ff00"
    else:
        summary += (
            f":rotating_light:*[UPDATED] AWS Health reported an issue with the {service.upper()} service in "
            f"the {region.upper()} region.*")
        color = "bb2124"

    message = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": summary
                }
            },

        ],
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "Account(s)",
                     "value": _affectedAccountIDs,
                     "short": True},
                    {"title": "Resource(s)",
                     "value": _affectedOrgEntities,
                     "short": True},
                    {"title": "Service", "value": service, "short": True},
                    {"title": "Region", "value": region, "short": True},
                    {"title": "Status", "value": statusCode, "short": True},
                    {"title": "Event ARN", "value": arn, "short": False},
                ],
            },
            {
                "color": color,
                "fields": [
                    {"title": "Diff(JA)",
                     "value": description_diff_text_ja,
                     "short": False},
                ],
            },
            {
                "color": color,
                "fields": [
                    {"title": "Updates(JA)",
                     "value": latestDescription_ja,
                     "short": False},
                ],
            },
        ]
    }
    return message


def generate_modify_email_message(
        affectedAccountIDs,
        affectedOrgEntities,
        service,
        region,
        statusCode,
        arn,
        latestDescription_ja,
        latestDescription_en,
        description_diff_text_ja,
        description_diff_text_en):

    if len(affectedOrgEntities) >= 1:
        _tmpList = list(map(lambda x: x['S'], affectedOrgEntities))
        _affectedOrgEntities = "\n".join(_tmpList)
    else:
        _affectedOrgEntities = "All resources in region"


    if len(affectedAccountIDs) >= 1:
        _tmpList = list(map(lambda x: x['S'], affectedAccountIDs))
        _affectedAccountIDs = "\n".join(_tmpList)
    else:
        _affectedAccountIDs = "All accounts in region"


    BODY_HTML = f"""
    <html>
        <body>
            <h>Greetings from AWS Health Aware,</h><br>
            <p>There is an AWS incident that is in effect which may likely impact your resources. Here are the details:<br><br>
            <b>Account(s):</b> {_affectedAccountIDs}<br>
            <b>Resource(s):</b> {_affectedOrgEntities}<br>
            <b>Service:</b> {service}<br>
            <b>Region:</b> {region}<br>
            <b>Status:</b> {statusCode}<br>
            <b>Event ARN:</b> {arn}<br>
            <b>Diff(JA):</b><br> {description_diff_text_ja} <br><br>
            <b>Updates(JA):</b><br>{latestDescription_ja} <br><br>

            </p>
        </body>
    </html>
"""
    return BODY_HTML


@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, context):
    logger.info(json.dumps(event))
    eventName = event['Records'][0]['eventName']
    logger.info(eventName)
    slack_message = ''
    email_message = ''

    if eventName == 'INSERT':
        secrets = get_secrets()
        new_event_record = event['Records'][0]['dynamodb']['NewImage']

        arn = new_event_record['arn']['S']
        statusCode = new_event_record['statusCode']['S']
        # PUBLIC | ACCOUNT_SPECIFIC
        eventScopeCode = new_event_record['eventScopeCode']['S']
        # issue | accountNotification | scheduledChange | investigation
        eventTypeCategory = new_event_record['eventTypeCategory']['S']
        # [a-zA-Z0-9\_\-]{3,100}
        eventTypeCode = new_event_record['eventTypeCode']['S']
        affectedAccountIDs = new_event_record['affectedAccountIDs']['L']
        affectedOrgEntities = new_event_record['affectedOrgEntities']['L']
        latestDescription_en = new_event_record['latestDescription']['S']
        latestDescription_ja = ''
        service = new_event_record['service']['S']
        region = new_event_record['region']['S']

        logger.info(affectedAccountIDs)

        # Get Account Config
        res = get_account_config("123456789012")
        _FilterCategoryList = res["FilterCategory"]
        _FilterServiceList = res["FilterService"]
        _FilterCodeList = res["FilterCode"]
        _EmailAddress = res["EmailAddress"]
        _SlackWebHookURL = res["SlackWebHookURL"]
        _TeamsWebHookURL = res["TeamsWebHookURL"]
        # _json = json.loads(_FilterCategory)

        logger.info(_FilterCategoryList)
        logger.info(_FilterServiceList)
        logger.info(_FilterCodeList)
        logger.info(_EmailAddress)
        logger.info(_SlackWebHookURL)
        logger.info(_TeamsWebHookURL)

        if eventTypeCategory in _FilterCategoryList:
            logger.info(
                "!!Filter Matched eventTypeCategory:" +
                eventTypeCategory)
            return None
        if service in _FilterServiceList:
            logger.info("!!Filter Matched service:" + service)
            return None
        if eventTypeCode in _FilterCodeList:
            logger.info("!!Filter Matched eventTypeCode:" + eventTypeCode)
            return None
        else:
            logger.info("Filter Not Matched")

        _event_latestDescription_split = latestDescription_en.split('\n\n')
        _event_latestDescription_ja_list = []
        for text in _event_latestDescription_split:
            _translated_text = get_translated_text(text)
            _event_latestDescription_ja_list.append(_translated_text)
        latestDescription_ja = '\n\n'.join(_event_latestDescription_ja_list)

        slack_message = generate_insert_slack_message(
            affectedAccountIDs,
            affectedOrgEntities,
            service,
            region,
            statusCode,
            arn,
            latestDescription_ja,
            latestDescription_en)
        # logger.info(slack_message)

        send_slack(slack_message, secrets['slack'])

        return None

    if eventName == 'MODIFY':
        # secrets = get_secrets()
        accounts = get_organizations_accounts()
        # logger.info(secrets)
        logger.info(accounts)
        new_event_record = event['Records'][0]['dynamodb']['NewImage']
        old_event_record = event['Records'][0]['dynamodb']['OldImage']

        arn = new_event_record['arn']['S']
        service = new_event_record['service']['S']
        # open | closed | upcoming
        statusCode = new_event_record['statusCode']['S']
        # PUBLIC | ACCOUNT_SPECIFIC
        eventScopeCode = new_event_record['eventScopeCode']['S']
        # issue | accountNotification | scheduledChange | investigation
        eventTypeCategory = new_event_record['eventTypeCategory']['S']
        # [a-zA-Z0-9\_\-]{3,100}
        eventTypeCode = new_event_record['eventTypeCode']['S']
        affectedAccountIDs = new_event_record['affectedAccountIDs']['L']
        affectedOrgEntities = new_event_record['affectedOrgEntities']['L']
        latestDescription_en = new_event_record['latestDescription']['S']
        region = new_event_record['region']['S']
        latestDescription_ja = ''

        logger.info(affectedAccountIDs)

        # Translate Description
        _event_latestDescription_split = latestDescription_en.split('\n\n')
        _event_latestDescription_ja_list = []
        for text in _event_latestDescription_split:
            _translated_text = get_translated_text(text)
            _event_latestDescription_ja_list.append(_translated_text)
        latestDescription_ja = '\n\n'.join(_event_latestDescription_ja_list)

        # Generate Diff
        diff = difflib.Differ()
        description_diff_text_en = get_discription_diff(
            new_event_record['latestDescription']['S'],
            old_event_record['latestDescription']['S'])
        if len(description_diff_text_en) == 0:
            description_diff_text_ja = "差分なし"
        else:
            description_diff_text_ja = get_translated_text(
                description_diff_text_en)

        old_event_record['latestDescription']['S'] = ''
        new_event_record['latestDescription']['S'] = ''
        old_event_record_line = to_string_lines(old_event_record)
        new_event_record_line = to_string_lines(new_event_record)
        # output_diff = diff.compare(
        #     old_event_record_line,
        #     new_event_record_line)

        slack_message = generate_modify_slack_message(
            affectedAccountIDs,
            affectedOrgEntities,
            service,
            region,
            statusCode,
            arn,
            latestDescription_ja,
            latestDescription_en,
            description_diff_text_ja,
            description_diff_text_en
        )
        email_message = generate_modify_email_message(
            affectedAccountIDs,
            affectedOrgEntities,
            service,
            region,
            statusCode,
            arn,
            latestDescription_ja.replace('\n\n','<br><br>'),
            latestDescription_en.replace('\n\n','<br><br>'),
            description_diff_text_ja,
            description_diff_text_en
        )

        # loop for AccountIDs

        if eventScopeCode == "ACCOUNT_SPECIFIC":
            for affectedAccountID in affectedAccountIDs:
                _AccountID = affectedAccountID['S']
                logger.info(_AccountID)

                # Get Account Config
                res = get_account_config(_AccountID)
                
                _FilterCategoryList = res.get("FilterCategory",[])
                logger.info(_FilterCategoryList)
                # FilterCategoryList = [x['S'] for x in _FilterCategoryList]
                
                _FilterServiceList = res.get("FilterService",[])
                logger.info(_FilterServiceList)
                # FilterServiceList = [x['S'] for x in _FilterServiceList]
                
                
                _FilterCodeList = res.get("FilterCode",[])
                logger.info(_FilterCodeList)
                # FilterCodeList = [x['S'] for x in _FilterCodeList]

                _EmailAddress = res.get("EmailAddress","")
                _SlackWebHookURL = res.get("SlackWebHookURL","")
                _TeamsWebHookURL = res.get("TeamsWebHookURL","")
                # _json = json.loads(_FilterCategory)

                # logger.info(res)

                if eventTypeCategory in _FilterCategoryList:
                    logger.info(
                        "!!!Filter Matched eventTypeCategory:" +
                        eventTypeCategory + "!!!")
                    continue
                if service in _FilterServiceList:
                    logger.info("!!!Filter Matched service:" + service + "!!!")
                    continue
                if eventTypeCode in _FilterCodeList:
                    logger.info("!!!Filter Matched eventTypeCode:" + eventTypeCode + "!!!")
                    continue
                else:
                    logger.info("Filter Not Matched")
                    logger.info(_SlackWebHookURL)
                    # Send Slack Message
                    if _SlackWebHookURL != "":
                        send_slack(slack_message, _SlackWebHookURL)
                    # Send Email Message
                    if _EmailAddress != "":
                        _EmailAddressList = []
                        _EmailAddressList.append(_EmailAddress)
                        send_email(email_message,_EmailAddressList)



        elif eventScopeCode == "PUBLIC":
            logger.info("PUBLICCC")


        return None
