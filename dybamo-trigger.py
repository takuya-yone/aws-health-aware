import json

def send_org_alert(event_details, affected_org_accounts, affected_org_entities, event_type):
    slack_url = get_secrets()["slack"]
    teams_url = get_secrets()["teams"]
    chime_url = get_secrets()["chime"]
    SENDER = os.environ['FROM_EMAIL']
    RECIPIENT = os.environ['TO_EMAIL']
    event_bus_name = get_secrets()["eventbusname"]

    if "None" not in event_bus_name:
        try:
            print("Sending the org alert to Event Bridge")
            send_to_eventbridge(
                get_org_message_for_eventbridge(event_details, event_type, affected_org_accounts,
                                                affected_org_entities),
                event_type, event_bus_name)
        except HTTPError as e:
            print("Got an error while sending message to EventBridge: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    if "hooks.slack.com/services" in slack_url:
        try:
            print("Sending the alert to Slack Webhook Channel")
            send_to_slack(
                get_org_message_for_slack(event_details, event_type, affected_org_accounts, affected_org_entities, slack_webhook="webhook"),
                slack_url)
        except HTTPError as e:
            print("Got an error while sending message to Slack: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    if "hooks.slack.com/workflows" in slack_url:
        try:
            print("Sending the alert to Slack Workflow Channel")
            send_to_slack(
                get_org_message_for_slack(event_details, event_type, affected_org_accounts, affected_org_entities, slack_webhook="workflow"),
                slack_url)
        except HTTPError as e:
            print("Got an error while sending message to Slack: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass            
    if "office.com/webhook" in teams_url:
        try:
            print("Sending the alert to Teams")
            send_to_teams(
                get_org_message_for_teams(event_details, event_type, affected_org_accounts, affected_org_entities),
                teams_url)
        except HTTPError as e:
            print("Got an error while sending message to Teams: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    # validate sender and recipient's email addresses
    if "none@domain.com" not in SENDER and RECIPIENT:
        try:
            print("Sending the alert to the emails")
            send_org_email(event_details, event_type, affected_org_accounts, affected_org_entities)
        except HTTPError as e:
            print("Got an error while sending message to Email: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass
    if "hooks.chime.aws/incomingwebhooks" in chime_url:
        try:
            print("Sending the alert to Chime channel")
            send_to_chime(
                get_org_message_for_chime(event_details, event_type, affected_org_accounts, affected_org_entities),
                chime_url)
        except HTTPError as e:
            print("Got an error while sending message to Chime: ", e.code, e.reason)
        except URLError as e:
            print("Server connection failed: ", e.reason)
            pass


def send_to_slack(message, webhookurl):
    slack_message = message
    req = Request(webhookurl, data=json.dumps(slack_message).encode("utf-8"),
                  headers={'content-type': 'application/json'})
    try:
        response = urlopen(req)
        response.read()
    except HTTPError as e:
        print("Request failed : ", e.code, e.reason)
    except URLError as e:
        print("Server connection failed: ", e.reason, e.reason)


def lambda_handler(event, context):
    # TODO implement
    print(json.dumps(event))
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
