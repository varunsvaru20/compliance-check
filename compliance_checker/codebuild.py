import boto3
from botocore.exceptions import ClientError
from compliance_checker.utils import check_tags, logger

# AWS Client
codebuild_client = boto3.client('codebuild')

#CodeBuild
def check_codebuild_project_compliance(resource_id):
    """
    Check compliance of an AWS CodeBuild project based on tags.
    :param resource_id: The ARN of the CodeBuild project
    :return: Tuple (is_compliant: bool, message: str)
    """
    try:
        # Describe the CodeBuild project
        response = boto3.client('codebuild').batch_get_projects(names=[resource_id.split('/')[-1]])
        projects = response.get('projects', [])
        if not projects:
            return False, f"CodeBuild project {resource_id} not found. Non-compliant."

        project = projects[0]
        tags = project.get('tags', [])
        return check_tags(tags, 'AWS::CodeBuild::Project', resource_id)

    except ClientError as e:
        logger.error(f"Error describing CodeBuild project {resource_id}: {e}")
        return False, f"Error occurred while checking CodeBuild project {resource_id}. Non-compliant."
