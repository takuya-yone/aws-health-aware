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


@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, context):
    logger.info(json.dumps(event))
    logger.info(json.loads(event['Records'][0]['body']))
    # eventName = event['Records'][0]['eventName']
    # logger.info(eventName)
