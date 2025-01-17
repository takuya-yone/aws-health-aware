import json
import boto3
from boto3.session import Session
import os
import difflib
from dateutil import parser
from datetime import datetime, timedelta
from urllib.request import Request, urlopen, URLError, HTTPError
from botocore.exceptions import ClientError
import difflib
from pprint import pformat
import hashlib


from aws_lambda_powertools import Logger
from aws_lambda_powertools import Tracer

region_name = os.environ['AWS_REGION']
tracer = Tracer()
logger = Logger()


DYNAMO_ACCOUNT_CONFIG_TABLE_NAME = os.environ['DYNAMO_ACCOUNT_CONFIG_TABLE_NAME']
ASSUME_ROLE_ARN = "arn:aws:iam::023829981675:role/AHA-Deployment-LambdaExecutionRole-1CTC9R0J2X0RV"


def myconverter(json_object):
    if isinstance(json_object, datetime):
        return json_object.__str__()


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


def get_ops_item_id(arn, account_id):
    ssm_client = boto3.client('ssm')
    _HashedArn = hashlib.sha256(arn.encode()).hexdigest()
    print(arn, _HashedArn)
    response = ssm_client.describe_ops_items(
        OpsItemFilters=[
            {
                'Key': 'OperationalDataValue',
                'Values': [
                    _HashedArn
                ],
                'Operator': 'Equal'
            },
            {
                'Key': 'Status',
                'Values': [
                    'Open', 'InProgress'
                ],
                'Operator': 'Equal'
            }
        ]
    )
    logger.info(response)
    OpsItemSummaries = response.get('OpsItemSummaries')
    OpsItemId = [x for x in OpsItemSummaries if x['OperationalData']
                 ['Account']['Value'] == str(account_id)][0]['OpsItemId']
    return OpsItemId


def update_ops_item(ops_item_id, description):
    ssm_client = boto3.client('ssm')
    response = ssm_client.update_ops_item(
        OpsItemId=ops_item_id,
        Description=description
    )
    logger.info(response)
    return response


def create_ops_item(description, priority, severity, title, arn, account):
    ssm_client = boto3.client('ssm')
    response = ssm_client.create_ops_item(
        Description=description,
        Priority=priority,
        Source='AHA-Custom',
        Title=title,
        OperationalData={
            'CreatedBy': {
                'Value': 'AHA-Custom',
                'Type': 'SearchableString'
            },
            'Arn': {
                'Value': arn,
                'Type': 'SearchableString'
            },
            'HashedArn': {
                'Value': hashlib.sha256(arn.encode()).hexdigest(),
                'Type': 'SearchableString'
            },
            'Account': {
                'Value': account,
                'Type': 'SearchableString'
            }
        },
        Severity=str(severity),
    )
    logger.info(response)
    return response.get('OpsItemId')


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


def send_slack(message, webhookurl):
    slack_message = message
    req = Request(webhookurl, data=json.dumps(slack_message).encode("utf-8"),
                  headers={'content-type': 'application/json'})
    print('------ send Slack message! ------')
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
    print('------ send Email message! ------')
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


def generate_insert_email_message(
        affectedAccountIDs,
        affectedOrgEntities,
        service,
        region,
        statusCode,
        arn,
        latestDescription_ja,
        latestDescription_en):

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
            <b>Updates(JA):</b><br>{latestDescription_ja} <br><br>

            </p>
        </body>
    </html>
"""
    return BODY_HTML


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
    accounts = get_organizations_accounts()

    if eventName == 'INSERT':

        new_event_record = event['Records'][0]['dynamodb']['NewImage']

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

        new_event_record['latestDescription']['S'] = ''
        new_event_record_line = to_string_lines(new_event_record)
        # output_diff = diff.compare(
        #     old_event_record_line,
        #     new_event_record_line)

        slack_message = generate_insert_slack_message(
            affectedAccountIDs,
            affectedOrgEntities,
            service,
            region,
            statusCode,
            arn,
            latestDescription_ja,
            latestDescription_en
        )
        email_message = generate_insert_email_message(
            affectedAccountIDs,
            affectedOrgEntities,
            service,
            region,
            statusCode,
            arn,
            latestDescription_ja.replace('\n\n', '<br><br>'),
            latestDescription_en.replace('\n\n', '<br><br>')
        )

        # loop for AccountIDs

        if eventScopeCode == "ACCOUNT_SPECIFIC":
            for affectedAccountID in affectedAccountIDs:
                _AccountID = affectedAccountID['S']
                # logger.info(_AccountID)

                # Get Account Alias
                account_alias = [x for x in accounts['Accounts']
                                 if x['Id'] == _AccountID][0]['Name']
                # logger.info(account_alias)
                print(
                    '-- AccountID:{}, AccountAlias:{} --'.format(_AccountID, account_alias))

                # Get Account Config
                res = get_account_config(_AccountID)
                _Priority = res.get("Priority", "")

                _FilterCategoryList = res.get("FilterCategory", [])
                logger.info(_FilterCategoryList)
                # FilterCategoryList = [x['S'] for x in _FilterCategoryList]

                _FilterServiceList = res.get("FilterService", [])
                logger.info(_FilterServiceList)
                # FilterServiceList = [x['S'] for x in _FilterServiceList]

                _FilterCodeList = res.get("FilterCode", [])
                logger.info(_FilterCodeList)
                # FilterCodeList = [x['S'] for x in _FilterCodeList]

                _EmailAddress = res.get("EmailAddress", "")
                _SlackWebHookURL = res.get("SlackWebHookURL", "")
                # _TeamsWebHookURL = res.get("TeamsWebHookURL", "")

                if eventTypeCategory in _FilterCategoryList:
                    logger.info(
                        "!!!Filter Matched eventTypeCategory:" +
                        eventTypeCategory + "!!!")
                    continue
                if service in _FilterServiceList:
                    logger.info("!!!Filter Matched service:" + service + "!!!")
                    continue
                if eventTypeCode in _FilterCodeList:
                    logger.info(
                        "!!!Filter Matched eventTypeCode:" +
                        eventTypeCode +
                        "!!!")
                    continue
                else:
                    logger.info("Filter Not Matched")

                    # Create OpsItem
                    _title = f"{service.upper()} in {region.upper()} region ({_AccountID}) "
                    create_ops_item(
                        latestDescription_ja, 4, 3, _title, arn, _AccountID)

                    # Send Slack Message
                    logger.info(_SlackWebHookURL)
                    if _SlackWebHookURL != "":
                        send_slack(slack_message, _SlackWebHookURL)
                    # Send Email Message
                    if _EmailAddress != "":
                        if _Priority == "HIGH" or _Priority == "MIDDLE":
                            _EmailAddressList = []
                            _EmailAddressList.append(_EmailAddress)
                            send_email(email_message, _EmailAddressList)

        elif eventScopeCode == "PUBLIC":
            logger.info("PUBLICCC")

            _AccountID = "PUBLIC"
            print('-- AccountID:{} --'.format(_AccountID))

            # Get Account Config
            res = get_account_config(_AccountID)
            _Priority = res.get("Priority", "")

            _FilterCategoryList = res.get("FilterCategory", [])
            logger.info(_FilterCategoryList)
            # FilterCategoryList = [x['S'] for x in _FilterCategoryList]

            _FilterServiceList = res.get("FilterService", [])
            logger.info(_FilterServiceList)
            # FilterServiceList = [x['S'] for x in _FilterServiceList]

            _FilterCodeList = res.get("FilterCode", [])
            logger.info(_FilterCodeList)
            # FilterCodeList = [x['S'] for x in _FilterCodeList]

            _EmailAddress = res.get("EmailAddress", "")
            _SlackWebHookURL = res.get("SlackWebHookURL", "")
            # _TeamsWebHookURL = res.get("TeamsWebHookURL", "")

            if eventTypeCategory in _FilterCategoryList:
                logger.info(
                    "!!!Filter Matched eventTypeCategory:" +
                    eventTypeCategory + "!!!")
            if service in _FilterServiceList:
                logger.info("!!!Filter Matched service:" + service + "!!!")
            if eventTypeCode in _FilterCodeList:
                logger.info(
                    "!!!Filter Matched eventTypeCode:" +
                    eventTypeCode +
                    "!!!")
            else:
                logger.info("Filter Not Matched")

                # Create OpsItem
                _title = f"{service.upper()} in {region.upper()} region ({_AccountID}) "
                create_ops_item(latestDescription_ja, 4,
                                3, _title, arn, _AccountID)
                # Send Slack Message
                logger.info(_SlackWebHookURL)
                if _SlackWebHookURL != "":
                    send_slack(slack_message, _SlackWebHookURL)
                # Send Email Message
                if _EmailAddress != "":
                    if _Priority == "HIGH" or _Priority == "MIDDLE":
                        _EmailAddressList = []
                        _EmailAddressList.append(_EmailAddress)
                        send_email(email_message, _EmailAddressList)

    if eventName == 'MODIFY':
        # client = boto3.client('sts')
        # account_id = client.get_caller_identity()["Account"]
        # userid = client.get_caller_identity()["UserId"]
        # arn = client.get_caller_identity()["Arn"]
        # print(account_id,userid,arn)
        # # client = boto3.client('sts')
        # response = client.assume_role(
        #         RoleArn=ASSUME_ROLE_ARN,
        #         RoleSessionName="HealthSession"
        #     )
        # print(response)

        # session = Session(
        #     aws_access_key_id=response['Credentials']['AccessKeyId'],
        #     aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        #     aws_session_token=response['Credentials']['SessionToken'],
        #     region_name=region_name
        # )
        # print(session)

        # health_client = session.client('health')
        # org_event_paginator = health_client.get_paginator('describe_events_for_organization')
        # org_event_page_iterator = org_event_paginator.paginate()
        # for response in org_event_page_iterator:
        #     events = response.get('events', [])
        #     aws_events = json.dumps(events,default=myconverter)
        #     aws_events = json.loads(aws_events)
        #     print('Event(s) Received: ', json.dumps(aws_events))

        # logger.info(secrets)
        # logger.info(accounts)
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
            latestDescription_ja.replace('\n\n', '<br><br>'),
            latestDescription_en.replace('\n\n', '<br><br>'),
            description_diff_text_ja,
            description_diff_text_en
        )

        # loop for AccountIDs

        if eventScopeCode == "ACCOUNT_SPECIFIC":
            for affectedAccountID in affectedAccountIDs:
                _AccountID = affectedAccountID['S']
                # logger.info(_AccountID)

                # Get Account Alias
                account_alias = [x for x in accounts['Accounts']
                                 if x['Id'] == _AccountID][0]['Name']
                # logger.info(account_alias)
                print(
                    '-- AccountID:{}, AccountAlias:{} --'.format(_AccountID, account_alias))

                # Get Account Config
                res = get_account_config(_AccountID)
                _Priority = res.get("Priority", "")

                _FilterCategoryList = res.get("FilterCategory", [])
                logger.info(_FilterCategoryList)
                # FilterCategoryList = [x['S'] for x in _FilterCategoryList]

                _FilterServiceList = res.get("FilterService", [])
                logger.info(_FilterServiceList)
                # FilterServiceList = [x['S'] for x in _FilterServiceList]

                _FilterCodeList = res.get("FilterCode", [])
                logger.info(_FilterCodeList)
                # FilterCodeList = [x['S'] for x in _FilterCodeList]

                _EmailAddress = res.get("EmailAddress", "")
                _SlackWebHookURL = res.get("SlackWebHookURL", "")
                # _TeamsWebHookURL = res.get("TeamsWebHookURL", "")

                if eventTypeCategory in _FilterCategoryList:
                    logger.info(
                        "!!!Filter Matched eventTypeCategory:" +
                        eventTypeCategory + "!!!")
                    continue
                if service in _FilterServiceList:
                    logger.info("!!!Filter Matched service:" + service + "!!!")
                    continue
                if eventTypeCode in _FilterCodeList:
                    logger.info(
                        "!!!Filter Matched eventTypeCode:" +
                        eventTypeCode +
                        "!!!")
                    continue
                else:
                    logger.info("Filter Not Matched")

                    # Update OpsItem
                    ops_item_id = get_ops_item_id(arn, _AccountID)
                    update_ops_item(ops_item_id, latestDescription_ja)

                    logger.info(_SlackWebHookURL)
                    # Send Slack Message
                    if _SlackWebHookURL != "":
                        send_slack(slack_message, _SlackWebHookURL)
                    # Send Email Message
                    if _EmailAddress != "":
                        if _Priority == "HIGH" or _Priority == "MIDDLE":
                            _EmailAddressList = []
                            _EmailAddressList.append(_EmailAddress)
                            send_email(email_message, _EmailAddressList)

        elif eventScopeCode == "PUBLIC":
            logger.info("PUBLICCC")

            _AccountID = "PUBLIC"
            print('-- AccountID:{} --'.format(_AccountID))

            # Get Account Config
            res = get_account_config(_AccountID)
            _Priority = res.get("Priority", "")

            _FilterCategoryList = res.get("FilterCategory", [])
            logger.info(_FilterCategoryList)
            # FilterCategoryList = [x['S'] for x in _FilterCategoryList]

            _FilterServiceList = res.get("FilterService", [])
            logger.info(_FilterServiceList)
            # FilterServiceList = [x['S'] for x in _FilterServiceList]

            _FilterCodeList = res.get("FilterCode", [])
            logger.info(_FilterCodeList)
            # FilterCodeList = [x['S'] for x in _FilterCodeList]

            _EmailAddress = res.get("EmailAddress", "")
            _SlackWebHookURL = res.get("SlackWebHookURL", "")
            # _TeamsWebHookURL = res.get("TeamsWebHookURL", "")

            if eventTypeCategory in _FilterCategoryList:
                logger.info(
                    "!!!Filter Matched eventTypeCategory:" +
                    eventTypeCategory + "!!!")
            if service in _FilterServiceList:
                logger.info("!!!Filter Matched service:" + service + "!!!")
            if eventTypeCode in _FilterCodeList:
                logger.info(
                    "!!!Filter Matched eventTypeCode:" +
                    eventTypeCode +
                    "!!!")
            else:
                logger.info("Filter Not Matched")
                # Update OpsItem
                ops_item_id = get_ops_item_id(arn, _AccountID)
                update_ops_item(ops_item_id, latestDescription_ja)
                print(ops_item_id)

                logger.info(_SlackWebHookURL)
                # Send Slack Message
                if _SlackWebHookURL != "":
                    send_slack(slack_message, _SlackWebHookURL)
                # Send Email Message
                if _EmailAddress != "":
                    if _Priority == "HIGH" or _Priority == "MIDDLE":
                        _EmailAddressList = []
                        _EmailAddressList.append(_EmailAddress)
                        send_email(email_message, _EmailAddressList)
        return None
