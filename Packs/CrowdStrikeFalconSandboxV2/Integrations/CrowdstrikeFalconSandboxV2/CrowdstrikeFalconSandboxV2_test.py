"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io

import pytest

from Packs.CrowdStrikeFalconSandboxV2.Integrations.CrowdstrikeFalconSandboxV2.CrowdstrikeFalconSandboxV2 import *

BASE_URL = 'https://test.com'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


client = Client(base_url=BASE_URL,
                verify=False,
                proxy=False,
                headers={})


def test_validated_search_terms():
    """

    Given:
        - query arguments that need to be converted

    When:
        - Turning demisto args into query args

    Then:
        - We get proper key-val pairs
    """
    pre_validation = {"hello": "world", "verdict": 'NoSpecificThreat'}
    post_validation = validated_search_terms(pre_validation)
    assert post_validation == {'hello': 'world', 'verdict': 3}


def test_validated_search_terms():
    """
    Given:
        - A bad country code

    When:
        - Turning demisto args into query args

    Then:
        - We get an error
    """
    pre_validation = {"country": "US", "verdict": 'NoSpecificThreat'}
    with pytest.raises(ValueError) as e:
        validated_search_terms(pre_validation)
    if not e:
        assert False
    else:
        assert e.value.args[0] == 'Country ISO code should be 3 characters long'


@pytest.mark.parametrize('demisto_args, st_args', [
    ({'query': 'country:USA,port:8080'}, {'country': 'USA', 'port': '8080'})
    , ({'country': 'USA', 'port': '8080'}, {'country': 'USA', 'port': '8080'})])
def test_get_search_term_args(demisto_args, st_args):
    """

    Given:
        - arguments coming in as query or not

    When:
        - Turning demisto args into query args

    Then:
        - We get results regardless of how it came in
    """
    assert st_args == get_search_term_args(demisto_args)


@pytest.mark.parametrize('query_string, query_dict',
                         [('hello:world,three:split:fine,heelo:, another: arg ',
                           {'hello': 'world', 'three': 'split:fine', 'another': 'arg'})
                             , ('arg1 :val1, arg2: val2  ', {'arg1': 'val1', 'arg2': 'val2'})
                          ])
def test_split_query_to_term_args(query_string, query_dict):
    """

   Given:
       - arguments coming in as joint query string

   When:
       - Turning demisto args into query args

   Then:
       - Query argument gets parsed properly
    """
    assert query_dict == split_query_to_term_args(query_string)


def test_results_in_progress_polling_true(requests_mock):
    """

    Given:
      - result request, polling true

    When:
      - result response in progress

    Then:
      - Get a scheduledcommand result
    """

    key = "dummy_key"
    filetype = "pdf"
    args = {'JobID': key, 'Polling': True, 'file-type': 'pdf'}
    requests_mock.get(BASE_URL + f"/report/{key}/report/{filetype}", status_code=404)
    requests_mock.get(BASE_URL + f"/report/{key}/state", json={'state' : 'IN_PROGRESS'})

    response = crowdstrike_result_command(client, args)
    sc = response.scheduled_command
    assert sc._args['Polling']
    assert sc._args['JobID'] == key


def test_map_dict_keys():
    orig = {'propertyName': 'propertyValue', 'a': 'b', 'x': 'y'}

    res = map_dict_keys(orig, {'a': 'c', 'x': 'z'}, True)
    assert res['c'] == 'b'
    assert res.get('.propertyName', None) is None

    res = map_dict_keys(orig, {'a': 'c', 'x': 'z'}, False)
    assert res['z'] == 'y'
    assert res['propertyName'] == 'propertyValue'
