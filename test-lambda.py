services = [{"S": "AWS_ACCOUNT"},{"S": "EC2"}]


listss = list(map(lambda x: x['S'], services))

print(listss)