import json
import boto3
import os
import hashlib


from aws_lambda_powertools import Logger
from aws_lambda_powertools import Tracer

region_name = os.environ['AWS_REGION']
tracer = Tracer()
logger = Logger()


import json
import boto3
import os
import hashlib


from aws_lambda_powertools import Logger
from aws_lambda_powertools import Tracer

region_name = os.environ['AWS_REGION']
tracer = Tracer()
logger = Logger()


def get_ops_item(arn):
    ssm_client = boto3.client('ssm')
    _HashedArn = hashlib.sha256(arn.encode()).hexdigest()
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
                    'Open','InProgress'
                ],
                'Operator': 'Equal'
            }
        ]
    )
    logger.info(response)
    logger.info(len(response.get('OpsItemSummaries')))
    return None


@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=False)
def lambda_handler(event, context):
    # logger.info(json.dumps(event))
    get_ops_item()



@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=False)
def lambda_handler(event, context):
    # logger.info(json.dumps(event))
    get_ops_item()
