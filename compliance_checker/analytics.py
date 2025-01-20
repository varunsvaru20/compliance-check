import boto3
from botocore.exceptions import ClientError
from compliance_checker.utils import check_tags, logger

# AWS Client
athena_client = boto3.client('athena')
cleanrooms_client = boto3.client('cleanrooms')
glue_client = boto3.client('glue')
lakeformation_client = boto3.client('lakeformation')
opensearch_client = boto3.client('opensearch')

#Athena
def describe_athena_resource(resource_id, resource_type, api_call):
    """Helper function to describe Athena resources and handle exceptions."""
    try:
        response = api_call(resource_id)
        if resource_type == 'AWS::Athena::WorkGroup':
            return response.get('WorkGroups', [{}])[0]
        elif resource_type == 'AWS::Athena::DataCatalog':
            return response.get('DataCatalogsSummary', [{}])[0]
        elif resource_type == 'AWS::Athena::NamedQuery':
            return response.get('NamedQueries', [{}])[0]
        else:
            raise ValueError(f"Unsupported resource type: {resource_type}")
    except ClientError as e:
        logger.error(f"Error describing {resource_type} ({resource_id}): {e}")
        raise


def check_athena_resource_compliance(resource_id, resource_type):
    """Function to check Athena resource compliance."""
    api_calls = {
        'AWS::Athena::WorkGroup': lambda rid: athena_client.get_work_group(WorkGroup=rid),
        'AWS::Athena::DataCatalog': lambda rid: athena_client.list_data_catalogs(),
        'AWS::Athena::NamedQuery': lambda rid: athena_client.get_named_query(NamedQueryId=rid),
    }

    if resource_type not in api_calls:
        return True, f"Resource type {resource_type} is not explicitly checked. Assuming compliance."

    response = describe_athena_resource(resource_id, resource_type, api_calls[resource_type])
    if not response:
        return False, f"Resource {resource_type} ({resource_id}) could not be described. Non-compliant."

    tags = response.get('Tags', []) if 'Tags' in response else []
    return check_tags(tags, resource_type, resource_id)

#AWS CleanRooms
def check_clean_rooms_compliance(resource_id, resource_type):
    """
    Checks compliance for AWS Clean Rooms resources.
    """
    try:
        if resource_type == 'AWS::CleanRooms::Collaboration':
            response = cleanrooms_client.get_collaboration(CollaborationIdentifier=resource_id)
            tags = response.get('Tags', [])
        elif resource_type == 'AWS::CleanRooms::ConfiguredTable':
            response = cleanrooms_client.get_configured_table(ConfiguredTableIdentifier=resource_id)
            tags = response.get('Tags', [])
        elif resource_type == 'AWS::CleanRooms::ConfiguredTableAssociation':
            response = cleanrooms_client.get_configured_table_association(ConfiguredTableAssociationIdentifier=resource_id)
            tags = response.get('Tags', [])
        else:
            return True, f"Resource type {resource_type} is not explicitly checked. Assuming compliance."

        # Check compliance based on tags
        return check_tags(tags, resource_type, resource_id)

    except ClientError as e:
        logger.error(f"Error describing {resource_type} ({resource_id}): {e}")
        return False, f"Resource {resource_type} ({resource_id}) could not be described. Non-compliant."

#AWS Glue
def describe_glue_resource(resource_id, resource_type):
    """Helper function to describe AWS Glue resources and handle exceptions."""
    try:
        if resource_type == 'AWS::Glue::Job':
            return glue_client.get_job(JobName=resource_id)['Job']
        elif resource_type == 'AWS::Glue::Crawler':
            return glue_client.get_crawler(Name=resource_id)['Crawler']
        elif resource_type == 'AWS::Glue::Database':
            return glue_client.get_database(Name=resource_id)['Database']
        elif resource_type == 'AWS::Glue::Table':
            # Assuming `resource_id` contains the database name and table name as "database_name.table_name"
            database_name, table_name = resource_id.split('.', 1)
            return glue_client.get_table(DatabaseName=database_name, Name=table_name)['Table']
        else:
            raise ValueError(f"Unsupported Glue resource type: {resource_type}")
    except ClientError as e:
        logger.error(f"Error describing {resource_type} ({resource_id}): {e}")
        return None

def check_glue_resource_compliance(resource_id, resource_type):
    """Check compliance for AWS Glue resources."""
    resource = describe_glue_resource(resource_id, resource_type)
    if not resource:
        return False, f"Resource {resource_type} ({resource_id}) could not be described. Non-compliant."

    tags = resource.get('Tags', [])
    return check_tags(tags, resource_type, resource_id)

#AWS LakeFormation
def check_lake_formation_resource_compliance(resource_id, resource_type):
    """
    Check compliance for AWS Lake Formation resources and sub-resources.
    """
    try:
        if resource_type == "AWS::LakeFormation::Resource":
            # Get resource tags
            response = lakeformation_client.get_resource_lf_tags(
                Resource={
                    "Database": {"Name": resource_id}  # Adjust based on resource type
                }
            )
            tags = response.get("LFTagPolicy", {}).get("Expression", [])
        elif resource_type == "AWS::LakeFormation::Table":
            # Get table-level tags
            response = lakeformation_client.get_resource_lf_tags(
                Resource={
                    "Table": {
                        "DatabaseName": resource_id.get("DatabaseName"),
                        "Name": resource_id.get("TableName"),
                    }
                }
            )
            tags = response.get("LFTagPolicy", {}).get("Expression", [])
        elif resource_type == "AWS::LakeFormation::Permissions":
            # Permissions resource doesn't have tags; check if it's scoped correctly
            response = lakeformation_client.list_permissions(ResourceType="TABLE")
            permissions = response.get("PrincipalResourcePermissions", [])
            if not permissions:
                return False, f"Resource {resource_type} ({resource_id}) has no permissions assigned. Non-compliant."
            return True, "Resource is compliant based on permissions."
        else:
            return True, f"Resource type {resource_type} is not explicitly checked. Assuming compliance."

        # Check for compliance using helper function
        if not tags:
            return False, f"Resource {resource_type} ({resource_id}) has no Lake Formation tags. Non-compliant."

        tag_found = any(tag["TagKey"] == "access-team" and tag["TagValues"][0] == "omc" for tag in tags)
        if not tag_found:
            return False, f"Resource {resource_type} ({resource_id}) has 'access-team=omc' tag. Non-compliant."

        return True, "Resource is compliant."
    except ClientError as e:
        logger.error(f"Error describing Lake Formation {resource_type} ({resource_id}): {e}")
        return False, f"Error retrieving tags for resource {resource_id}: {e}"
    except Exception as e:
        logger.error(f"Unhandled error for Lake Formation {resource_type} ({resource_id}): {e}")
        raise

#AWS OpenSearch
def describe_opensearch_resource(resource_id):
    """Helper function to describe OpenSearch resources and handle exceptions."""
    try:
        response = opensearch_client.describe_domain(DomainName=resource_id)
        return response.get('DomainStatus', {})
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.warning(f"OpenSearch Domain {resource_id} not found.")
            return None
        logger.error(f"Error describing OpenSearch Domain {resource_id}: {e}")
        raise

def check_opensearch_compliance(resource_id):
    """Function to check OpenSearch domain compliance."""
    response = describe_opensearch_resource(resource_id)
    if not response:
        return False, f"OpenSearch Domain ({resource_id}) could not be described. Non-compliant."

    tags = opensearch_client.list_tags(ResourceArn=response['ARN']).get('TagList', [])
    compliant, message = check_tags(tags, 'AWS::OpenSearchService::Domain', resource_id)

    # Check additional compliance criteria (e.g., access policy, VPC configuration) if needed
    access_policies = response.get('AccessPolicies', '{}')
    if 'Principal' not in access_policies or 'AWS' not in access_policies:
        compliant = False
        message += " Access policy is not properly configured. Non-compliant."

    return compliant, message
