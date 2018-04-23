import json
import time

from botocore.exceptions import ClientError
from cloudaux.aws.sts import boto3_cached_conn

from repokid import LOGGER
import repokid.hooks as hooks
from repokid.hooks.cloudtrail import cloudtrail_utils as ct_utils  # assuming this hook is installed as cloudtrail

CONNECTION_DETAILS = {
    "account_number": "",  # account number for S3 object that contains these files
    "bucket_name": "",     # bucket name that contains these files
    "region": "",          # bucket region that contains these files

    # JSON file that contains a list of calls that should not be repoed
    # these are typically for calls such as S3 that may be enabled on a certain bucket, but are not enabled across all
    # buckets, so we don't want to assume the calls are all tracked.
    # See: Amazon S3 Object-Level Actions Tracked by CloudTrail Logging at
    # https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudtrail-logging.html
    "ct_no_repo": "<PATH>/ct_no_repo.json",
    # JSON file that contains a list of S3 calls that are safe to repo because they are always enabled.
    # See: Amazon S3 Bucket-Level Actions Tracked by CloudTrail Logging at
    # https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudtrail-logging.html
    "s3_repo_whitelist": "<PATH>/s3_repo_whitelist.json",
    # JSON file that contains a dictionary of the service and actions that have been observed along with the timestamp
    # for the last time they were observed. The format should be:
    # {
    #    "service:action": 1496337243,
    #    ...
    # }
    # Repokid will only repo actions that have been observed before and the observed time has to be longer than the
    # cutoff time (eg 90 days)
    "ct_observed_actions": "<PATH>/ct_observed_actions.json",
    # JSON file that contains a dictionary of the service and action in IAM and how it is recorded in CloudTrail in
    # case that they differ.  For example:
    # {
    #    "iam_service:iam:action": "cloudtrail_service:cloudtrail_action"
    # }
    "ct_to_policy_map": "<PATH>/ct_to_policy_map.json"
}


def _get_obj(key):
    resource = boto3_cached_conn('s3', service_type='resource', account_number=CONNECTION_DETAILS['account_number'],
                                 session_name='repokid', region=CONNECTION_DETAILS['region'])
    obj = resource.Object(bucket_name=CONNECTION_DETAILS['bucket_name'], key=key)
    f_data = obj.get()["Body"].read().decode('utf-8')
    j_data = json.loads(f_data)
    return j_data


try:
    CT_NO_REPO = _get_obj(CONNECTION_DETAILS['ct_no_repo'])

    CT_OBSERVED_ACTIONS = _get_obj(CONNECTION_DETAILS['ct_observed_actions'])

    CT_TO_POLICY_MAP = _get_obj(CONNECTION_DETAILS['ct_to_policy_map'])
    S3_REPO_WHITE_LIST = _get_obj(CONNECTION_DETAILS['s3_repo_whitelist'])
    INDEXES = ct_utils.indexes()
except (ClientError, ValueError, Exception) as e:
    LOGGER.error('Error during cloudtrail hook: {}'.format(e))


@hooks.implements_hook('DURING_REPOABLE_CALCULATION', 2)
def repo_cloud_trail(input_dict):
    # input_dict: account_number, role_name, potentially_repoable_permissions, minimum_age
    if input_dict['minimum_age'] > len(INDEXES):
        LOGGER.warning("Cloudtrail doesn't have {} days worth of data, skipping")
        return input_dict

    try:
        ct_used_actions = ct_utils.actor_usage(input_dict['role_name'], input_dict['account_number'], 'iamrole',
                                               INDEXES[:input_dict['minimum_age']], 'anything_but_denied')
    except Exception as e:
        LOGGER.warning("Unable to retrieve Cloudtrail data for role {}: {}".format(input_dict['role_name'], e))
        return input_dict

    ct_used_actions = [action.lower() for action in ct_used_actions]

    # we don't want to repo any permissions that have been observed inside our minimum age window because
    # the action could have been used, but cloudtrail support didn't exist
    observed_cutoff_time = int(time.time() - (input_dict['minimum_age'] * 86400))
    # valid actions for repo are those that have been observed before our cutoff time, chop off the date version if
    # present
    repoable_actions = set([action.split('20')[0] for action, observed in CT_OBSERVED_ACTIONS.items()
                           if observed < observed_cutoff_time])

    # filter out S3 actions that aren't in the whitelist
    repoable_actions = set([action for action in repoable_actions if
                           (not action.startswith('s3:') or action in S3_REPO_WHITE_LIST)])

    # actions are repoable if we have seen them before but don't see them for this role for time period and
    # they aren't in NO_REPO
    ct_says_removable = [action for action in repoable_actions if
                         action not in ct_used_actions and action not in CT_NO_REPO]

    # attempt to get CT -> action mapping, fall back on action, if mapping doesn't exist fall back to the action name
    repokid_ct_says_removable = [CT_TO_POLICY_MAP.get(ct_action, ct_action).lower() for ct_action in ct_says_removable]

    for permission_name, permission_decision in input_dict['potentially_repoable_permissions'].items():
        if permission_name in ct_used_actions and permission_decision.repoable:
            LOGGER.warning('Cloudtrail plugin disagrees with {} about permission: {} for role {}!  '
                           'CT says used, {} says not'.format(permission_decision.decider, permission_name,
                                                              input_dict['role_name'], permission_decision.decider))

        elif permission_name in repokid_ct_says_removable:
            permission_decision.repoable = True
            permission_decision.decider = ('Cloudtrail' if not permission_decision.decider
                                           else permission_decision.decider + ", Cloudtrail")

    # TODO: there is a contingency to be aware of - if Access Advisor says something in a service is used, cloudtrail
    # might have missed the call.  So if we're removing all of a service that access advisor says keep we might want
    # to check

    return input_dict
