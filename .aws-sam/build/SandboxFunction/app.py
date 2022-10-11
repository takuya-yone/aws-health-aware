import json
import boto3
import os


from aws_lambda_powertools import Logger
from aws_lambda_powertools import Tracer

region_name = os.environ['AWS_REGION']
tracer = Tracer()
logger = Logger()

def get_ops_item():
    ssm_client = boto3.client('ssm')
    response = ssm_client.describe_ops_items(Filters=[{'Name':'tag:Account','Values':['PUBLIC']}])
    logger.info(response)
    return None

@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=False)
def lambda_handler(event, context):
    # logger.info(json.dumps(event))
    get_ops_item()
    