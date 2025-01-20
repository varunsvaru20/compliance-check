import boto3
from botocore.exceptions import ClientError
from compliance_checker.utils import check_tags, logger

# AWS Client
events_client = boto3.client('events')
sns_client = boto3.client('sns')


#EventBridge
def describe_eventbridge_resource(resource_id, resource_type, api_call):
    """Helper function to describe EventBridge resources and handle exceptions."""
    try:
        response = api_call(resource_id)
        if resource_type == 'AWS::Events::Rule':
            return response.get('Rules', [{}])[0]
        elif resource_type == 'AWS::Events::EventBus':
            return response.get('EventBuses', [{}])[0]
        elif resource_type == 'AWS::Events::Target':
            return response.get('Targets', [{}])[0]
        else:
            raise ValueError(f"Unsupported EventBridge resource type: {resource_type}")
    except ClientError as e:
        logger.error(f"Error describing {resource_type} ({resource_id}): {e}")
        raise

def check_eventbridge_resource_compliance(resource_id, resource_type):
    """Check compliance for EventBridge resources."""
    api_calls = {
        'AWS::Events::Rule': lambda rid: boto3.client('events').describe_rule(Name=rid),
        'AWS::Events::EventBus': lambda rid: boto3.client('events').describe_event_bus(Name=rid),
        'AWS::Events::Target': lambda rid: boto3.client('events').list_targets_by_rule(Rule=rid),
    }

    if resource_type not in api_calls:
        return True, f"Resource type {resource_type} is not explicitly checked. Assuming compliance."

    response = describe_eventbridge_resource(resource_id, resource_type, api_calls[resource_type])
    if not response:
        return False, f"Resource {resource_type} ({resource_id}) could not be described. Non-compliant."

    # EventBridge resources often do not have tags. Add tagging checks if necessary.
    tags = response.get('Tags', [])
    return check_tags(tags, resource_type, resource_id)

#SNS
def check_sns_compliance(resource_id):
    """Check compliance of an SNS topic."""
    try:
        # Get the attributes of the SNS topic
        topic_attributes = sns_client.get_topic_attributes(TopicArn=resource_id)
        tags_response = sns_client.list_tags_for_resource(ResourceArn=resource_id)
        tags = tags_response.get('Tags', [])

        # Validate tags
        compliant, message = check_tags(tags, 'AWS::SNS::Topic', resource_id)
        if not compliant:
            return compliant, message

        # Additional checks for SNS topic attributes if needed
        # Example: Enforce encryption or specific attributes
        attributes = topic_attributes.get('Attributes', {})
        if 'KmsMasterKeyId' not in attributes or not attributes['KmsMasterKeyId']:
            return False, f"SNS Topic ({resource_id}) is not encrypted with a KMS key. Non-compliant."

        return True, "SNS Topic is compliant."

    except ClientError as e:
        logger.error(f"Error describing SNS Topic ({resource_id}): {e}")
        return False, f"Could not retrieve SNS Topic ({resource_id}). Non-compliant."

def check_sns_subscription_compliance(subscription_arn):
    """Check compliance of an SNS subscription."""
    try:
        # Get subscription attributes
        subscription_attributes = sns_client.get_subscription_attributes(SubscriptionArn=subscription_arn)

        # Example: Ensure RawMessageDelivery is disabled (if required for compliance)
        attributes = subscription_attributes.get('Attributes', {})
        if attributes.get('RawMessageDelivery') == 'true':
            return False, f"SNS Subscription ({subscription_arn}) has RawMessageDelivery enabled. Non-compliant."

        return True, "SNS Subscription is compliant."

    except ClientError as e:
        logger.error(f"Error describing SNS Subscription ({subscription_arn}): {e}")
        return False, f"Could not retrieve SNS Subscription ({subscription_arn}). Non-compliant."

def check_sns_resource_compliance(resource_id, resource_type):
    """Main compliance checker for SNS topics and subscriptions."""
    if resource_type == 'AWS::SNS::Topic':
        return check_sns_compliance(resource_id)
    elif resource_type == 'AWS::SNS::Subscription':
        return check_sns_subscription_compliance(resource_id)
    else:
        return True, f"Resource type {resource_type} is not explicitly checked. Assuming compliance."

#SQS
def check_sqs_compliance(resource_id):
    """
    Checks compliance for an SQS queue by verifying if the 'access-team=omc' tag is present.
    """
    try:
        response = sns_client.list_tags_for_resource(ResourceArn=resource_id)
        tags = response.get('Tags', [])
        return check_tags(tags, 'AWS::SQS::Queue', resource_id)
    except ClientError as e:
        logger.error(f"Error describing SQS queue ({resource_id}): {e}")
        raise
