from elasticsearch_dsl import Q, Search
from elasticsearch import Elasticsearch
import requests

CLOUDTRAIL_INDEX_EXPRESSION = '<INDEX_NAME_PATTERN>'
SERVER = '<ELASTIC_SEARCH_SERVER_HERE>'
TIMESTAMP = 'eventTime'  # field name of timestamp


def indexes():
    indexes = []
    response = requests.get("{}_aliases".format(SERVER))
    indexes = response.json().keys()
    indexes = sorted([index for index in indexes if CLOUDTRAIL_INDEX_EXPRESSION in index], reverse=True)

    return indexes


def filter_errors(s, errors):
    if errors and errors == 'code':
        s = s.filter("exists", field="errorCode")
        s = s.query(~Q("match", errorCode='AccessDenied'))
        s = s.query(~Q("match", errorCode='AccessDeniedException'))
        s = s.query(~Q("match", errorCode='Client.UnauthorizedOperation'))
    if errors and errors == 'access_denied':
        s = s.filter("terms", errorCode=['AccessDenied', 'AccessDeniedException', 'Client.UnauthorizedOperation'])
    if errors and errors == 'anything_but_denied':
        s = s.query(~Q("match", errorCode='AccessDenied'))
        s = s.query(~Q("match", errorCode='AccessDeniedException'))
        s = s.query(~Q("match", errorCode='Client.UnauthorizedOperation'))
    if not errors:
        s = s.filter("missing", field="errorCode")
    return s


def filter_account(s, account_numbers, tech):
    if type(account_numbers) is not list:
        account_numbers = [account_numbers]

    if tech == 'iamrole':
        s = s.filter('terms', ** {'userIdentity.sessionContext.sessionIssuer.accountId': account_numbers})
    elif tech == 'iamuser':
        s = s.filter('terms', ** {'userIdentity.accountId': account_numbers})
    return s


def paginate_query(s, count, page):
    start = (page-1)*count
    finish = count*page
    return s[start:finish]


def query_tech(s, tech, name):
    if type(name) is not list:
        name = [name]

    if tech == 'iamrole':
        return s.filter('terms', ** {'userIdentity.sessionContext.sessionIssuer.userName': name})
    elif tech == 'iamuser':
        return s.filter('terms', ** {'userIdentity.userName': name})


def actor_usage(name, account, tech, index, errors):
    client = Elasticsearch(SERVER, timeout=90)

    s = Search(using=client, index=index)
    s = query_tech(s, tech, name)
    s = filter_account(s, account, tech)
    s = filter_errors(s, errors)

    s.aggs.bucket('group_by_eventSource', 'terms', field='eventSource', size=2000) \
        .metric('group_by_eventName', 'terms', field='eventName', size=2000)

    response = s.execute()

    results = {}
    for event_source in response.aggregations.group_by_eventSource.buckets:
        for event_name in event_source.group_by_eventName.buckets:
            event_source_short = event_source.key.split('.amazonaws.com')[0]
            key = "{es}:{en}".format(es=event_source_short, en=event_name.key)
            if key in results:
                results[key] += event_name.doc_count
            else:
                results[key] = event_name.doc_count

    return [k for k in results.keys()]
