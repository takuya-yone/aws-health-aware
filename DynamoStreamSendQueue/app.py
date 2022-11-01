from email import message
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
QUEUE_NAME = os.environ['QUEUE_NAME']
tracer = Tracer()
logger = Logger()


def sqs_send_message(message_body):
    sqs = boto3.resource('sqs')
    queue = sqs.get_queue_by_name(QueueName=QUEUE_NAME)
    sqsresponse = queue.send_message(
        MessageBody=message_body,
        # MessageAttributes={
        #     'attr1': {
        #         'DataType': 'String',
        #         'StringValue': "value of attr1"
        #     },
        #     'attr2': {
        #         'DataType': 'String',
        #         'StringValue': "value of attr2"
        #     },
        #     'attr3': {
        #         'DataType': 'String',
        #         'StringValue': "value of attr3"
        #     }
        # }
    )
    logger.info(sqsresponse)


@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, context):
    # logger.info(json.dumps(event))
    # eventName = event['Records'][0]['eventName']
    # logger.info(eventName)
    message_body = json.dumps(event['Records'][0])
    logger.info(message_body)

    sqs_send_message(message_body)
