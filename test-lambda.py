import difflib
from pprint import pformat, pprint

def to_string_lines(obj):
    # dictのオブジェクトを文字列に変換＆改行で分割したリストを返却
    return pformat(obj,compact=True).split('\n')
    # return pprint(obj)

diff = difflib.Differ()

old_event_record = {'latestDescription': {'S': 'Current severity level: Operating normally\n\n[RESOLVED] CloudTrail event delivery delays\n\n[02:10 PM PDT] Between 09:33 AM and 12:57 PM PDT Increased latency of CloudTrail events in the US-EAST-1 Region causing CloudTrail events processing delays. We have resolved the issue all backlog events are in the process of backfilling will be completed by 3:30 PM PDT. The service is operating normally. \n\n[01:07 PM PDT] We are investigating increased latency of CloudTrail events causing CloudTrail events processing delays in the US-EAST-1 Region starting at 9:33 AM PDT. CloudTrail customers in US-EAST-1 Region will receive events with delay as high as 4 hours.  All new events after 12:57 PM PDT will be processed immediately. ETA for backlog consumption is 3:30 PM PDT.'}, 'added': {'S': '1662012811'}, 'service': {'S': 'CLOUDTRAIL'}, 'affectedOrgEntities': {'L': []}, 'lastUpdatedTime': {'S': '1660684205188'}, 'affectedAccountIDs': {'L': []}, 'arn': {'S': 'arn:aws:health:us-east-1::event/CLOUDTRAIL/AWS_CLOUDTRAIL_OPERATIONAL_ISSUE/AWS_CLOUDTRAIL_OPERATIONAL_ISSUE_CMVCT_166123123123133130680453'}, 'region': {'S': 'us-east-1'}, 'ttl': {'N': '1666476811'}, 'statusCode': {'S': 'closed'}}
new_event_record = {'latestDescription': {'S': 'Current severity level: Operating normally\n\n[RESOLVEeeeeeeeeeD] CloudTrail event delivery delays\n\n[02:10 PM PDT] Between 09:33 AM and 12:57 PM PDT Increased latency of CloudTrail events in the US-EAST-1 Region causing CloudTrail events processing delays. We have resolved the issue all backlog events are in the process of backfilling will be completed by 3:30 PM PDT. The service is operating normally. \n\n[01:07 PM PDT] We are investigating increased latency of CloudTrail events causing CloudTrail events processing delays in the US-EAST-1 Region starting at 9:33 AM PDT. CloudTrail customers in US-EAST-1 Region will receive events with delay as high as 4 hours.  All new events after 12:57 PM PDT will be processed immediately. ETA for backlog consumption is 3:30 PM PDT.'}, 'added': {'S': '16620128111'}, 'service': {'S': 'CLOUDTRAIL'}, 'affectedOrgEntities': {'L': []}, 'lastUpdatedTime': {'S': '1660684205188'}, 'affectedAccountIDs': {'L': []}, 'arn': {'S': 'arn:aws:health:us-east-1::event/CLOUDTRAIL/AWS_CLOUDTRAIL_OPERATIONAL_ISSUE/AWS_CLOUDTRAIL_OPERATIONAL_ISSUE_CMVCT_166123123123133130680453'}, 'region': {'S': 'us-east-1'}, 'ttl': {'N': '1666476811'}, 'statusCode': {'S': 'closed'}}

# print(old_event_record)
# print(new_event_record)
# print(output_diff)

# output_diff = diff.compare(old_event_record,new_event_record)


# old_event_record_line = to_string_lines(old_event_record)
# new_event_record_line = to_string_lines(new_event_record)

# output_diff = diff.compare(old_event_record_line,new_event_record_line)



old_event_record_latestDescription_list = (old_event_record['latestDescription']['S']).split('\n\n')
new_event_record_latestDescription_list = (new_event_record['latestDescription']['S']).split('\n\n')

old_event_record['latestDescription']['S']=''
new_event_record['latestDescription']['S']=''

old_event_record_line = to_string_lines(old_event_record)
new_event_record_line = to_string_lines(new_event_record)

output_diff = diff.compare(old_event_record_line,new_event_record_line)


print(list(set(old_event_record_latestDescription_list) - set(new_event_record_latestDescription_list)))
for data in output_diff:
    if data[0:1] in ['+', '-']:
        print(data)