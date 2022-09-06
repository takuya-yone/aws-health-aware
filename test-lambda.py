import os
import difflib
from pprint import pformat, pprint
import boto3

region_name = os.environ['AWS_REGION']


def to_string_lines(obj):
    # dictのオブジェクトを文字列に変換＆改行で分割したリストを返却
    return pformat(obj, compact=True).split('\n')
    # return pprint(obj)


def get_organizations_accounts():
    session = boto3.session.Session()
    org_client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    response = org_client.list_accounts()
    return response


def get_discription_diff(new_description, old_description):
    new_description_list = new_description.split('\n\n')
    old_description_list = old_description.split('\n\n')

    # diff_1 = set(new_description_list).difference(set(old_description_list))
    # diff_2 = set(old_description_list).difference(set(new_description_list))
    # diff_list = list(diff_1.union(diff_2))
    diff_list = list(set(new_description_list) - set(old_description_list))

    if len(diff_list) == 0:
        return ''
    else:
        return '\n\n'.join(text for text in diff_list)


diff = difflib.Differ()

new_event_record = {
    'latestDescription': {
        'S': 'Current severity level: Operating normally\n\n[RESOLVEEEED] CloudTrail event delivery delays\n\n[02:10 PM PDT] Between 09:33 AM and 12:57 PM PDT Increased latency of CloudTrail events in the US-EAST-1 Region causing CloudTrail events processing delays. We have resolved the issue all backlog events are in the process of backfilling will be completed by 3:30 PM PDT. The service is operating normally. \n\n[01:07 PM PDT] We are investigating increased latency of CloudTrail events causing CloudTrail events processing delays in the US-EAST-1 Region starting at 9:33 AM PDT. CloudTrail customers in US-EAST-1 Region will receive events with delay as high as 4 hours.  All new events after 12:57 PM PDT will be processed immediately. ETA for backlog consumption is 3:30 PM PDT.'},
    'added': {
        'S': '16620128111'},
    'service': {
        'S': 'CLOUDTRAIL'},
    'affectedOrgEntities': {
        'L': []},
    'lastUpdatedTime': {
        'S': '1660684205188'},
    'affectedAccountIDs': {
        'L': []},
    'arn': {
        'S': 'arn:aws:health:us-east-1::event/CLOUDTRAIL/AWS_CLOUDTRAIL_OPERATIONAL_ISSUE/AWS_CLOUDTRAIL_OPERATIONAL_ISSUE_CMVCT_166123123123133130680453'},
    'region': {
        'S': 'us-east-1'},
    'ttl': {
        'N': '1666476811'},
    'statusCode': {
        'S': 'closed'}}

old_event_record = {
    'latestDescription': {
        'S': 'Current severity level: Operating normally\n\n[RESOLVED] CloudTrail event delivery delays\n\n[02:10 PM PDT] Between 09:33 AM and 12:57 PM PDT Increased latency of CloudTrail events in the US-EAST-1 Region causing CloudTrail events processing delays. We have resolved the issue all backlog events are in the process of backfilling will be completed by 3:30 PM PDT. The service is operating normally. \n\n[01:07 PM PDT] We are investigating increased latency of CloudTrail events causing CloudTrail events processing delays in the US-EAST-1 Region starting at 9:33 AM PDT. CloudTrail customers in US-EAST-1 Region will receive events with delay as high as 4 hours.  All new events after 12:57 PM PDT will be processed immediately. ETA for backlog consumption is 3:30 PM PDT.'},
    'added': {
        'S': '1662012811'},
    'service': {
        'S': 'CLOUDTRAIL'},
    'affectedOrgEntities': {
        'L': []},
    'lastUpdatedTime': {
        'S': '1660684205188'},
    'affectedAccountIDs': {
        'L': []},
    'arn': {
        'S': 'arn:aws:health:us-east-1::event/CLOUDTRAIL/AWS_CLOUDTRAIL_OPERATIONAL_ISSUE/AWS_CLOUDTRAIL_OPERATIONAL_ISSUE_CMVCT_166123123123133130680453'},
    'region': {
        'S': 'us-east-1'},
    'ttl': {
        'N': '1666476811'},
    'statusCode': {
        'S': 'closed'}}


description_diff_text = get_discription_diff(
    new_event_record['latestDescription']['S'],
    old_event_record['latestDescription']['S'])

old_event_record['latestDescription']['S'] = ''
new_event_record['latestDescription']['S'] = ''
old_event_record_line = to_string_lines(old_event_record)
new_event_record_line = to_string_lines(new_event_record)
output_diff = diff.compare(old_event_record_line, new_event_record_line)


print(description_diff_text)

get_organizations_accounts()

for data in output_diff:
    if data[0:1] in ['+', '-']:
        print(data)
    # pass
