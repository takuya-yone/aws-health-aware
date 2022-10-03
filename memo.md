# Memo
- Health API Ref
  - https://docs.aws.amazon.com/health/latest/APIReference/API_Event.html
- DynamoTrigger用LambdaのRole
  - Streamの権限を追加
```Json
{
    "Action": [
        "dynamodb:GetShardIterator",
        "dynamodb:GetRecords",
        "dynamodb:ListStream",
        "dynamodb:DescribeStream"
    ],
    "Resource": "arn:aws:dynamodb:ap-northeast-1:xxxxxxxxxxxx:table/AHA-Deployment-DynamoDBTable-968VOP84UULQ/stream/*",
    "Effect": "Allow"
},
```
- 初期Lambdaとの差分
  - update_org_ddb
    - affected_org_entities をDynamoレコードに追加
    - service をDynamoレコードに追加
    - region をDynamoレコードに追加