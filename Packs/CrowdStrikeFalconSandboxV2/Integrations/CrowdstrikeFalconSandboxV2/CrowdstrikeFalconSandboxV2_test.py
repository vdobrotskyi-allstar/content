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


def test_validated_search_terms_bad_arg():
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
    state_call = requests_mock.get(BASE_URL + f"/report/{key}/state", json={'state': 'IN_PROGRESS'})

    response = crowdstrike_result_command(client, args)
    sc = response.scheduled_command
    assert state_call.called
    assert sc._args['Polling']
    assert sc._args['JobID'] == key
    assert sc._args['file-type'] == filetype
    assert sc._args['polled_once']


def test_results_in_progress_polling_true_with_file(requests_mock):
    """

    Given:
      - result request with file given, polling true

    When:
      - result response is ready

    Then:
      - Get a final result and a scan result
    """

    filetype = "pdf"
    hash_response_json = util_load_json('test_data/scan_response.json')

    args = {'file': 'abcd', 'environmentID': 300, 'Polling': True, 'file-type': filetype}
    raw_response_data = 'RawDataOfFileResult'
    key = get_api_id(args)
    assert key == 'abcd:300'

    requests_mock.get(BASE_URL + f"/report/{key}/report/{filetype}", status_code=200, text=raw_response_data)
    requests_mock.post(BASE_URL + "/search/hashes", json=hash_response_json)

    response = crowdstrike_result_command(client, args)

    assert isinstance(response, list)
    file_result, scan_result = response

    assert file_result['Type'] == 9
    assert file_result['File'].endswith("pdf")

    assert ['SUCCESS', 'SUCCESS'] == [o['state'] for o in scan_result.outputs]
    assert ['malicious', 'malicious'] == [o['verdict'] for o in scan_result.outputs]
    assert [False, False] == [o.bwc_fields['url_analysis'] for o in scan_result.indicators]


def test_results_in_progress_polling_false(requests_mock):
    """

    Given:
      - result request, polling false

    When:
      - result response in progress

    Then:
      - Get a 404 result
    """

    key = "dummy_key"
    filetype = "pdf"
    args = {'JobID': key, 'Polling': False, 'file-type': filetype}
    requests_mock.get(BASE_URL + f"/report/{key}/report/{filetype}", status_code=404)
    state_call = requests_mock.get(BASE_URL + f"/report/{key}/state", json={'state': 'IN_PROGRESS'})

    response = crowdstrike_result_command(client, args)

    assert not state_call.called
    assert not response.scheduled_command
    assert response.readable_output == 'Falcon Sandbox returned an error: status code 404, response: '


def test_crowdstrike_scan_command_polling_true(requests_mock):
    """

    Given:
      - result request, polling false

    When:
      - result response in progress

    Then:
      - Get a 404 result
    """
    requests_mock.post(BASE_URL + '/search/hashes', json=[])
    response = crowdstrike_scan_command(client, {"file": "filehash", "Polling": True})
    assert response.scheduled_command._args['file'] == 'filehash'
    assert response.scheduled_command._args['polled_once']


def test_crowdstrike_scan_command_polling_false(requests_mock):
    """

    Given:
      - result request, polling false

    When:
      - result response in progress

    Then:
      - Get a 404 result
    """
    requests_mock.post(BASE_URL + '/search/hashes', json=[])
    response = crowdstrike_scan_command(client, {"file": "filehash"})
    assert response.scheduled_command is None
    assert response.outputs == []


def test_results_in_progress_polling_true_error_state(requests_mock):
    """

    Given:
      - result request, polling false

    When:
      - result response in progress

    Then:
      - Get a 404 result
    """

    key = "dummy_key"
    filetype = "pdf"
    args = {'JobID': key, 'Polling': True, 'file-type': 'pdf'}
    requests_mock.get(BASE_URL + f"/report/{key}/report/{filetype}", status_code=404)
    requests_mock.get(BASE_URL + f"/report/{key}/state", json={'state': 'ERROR'})
    with pytest.raises(Exception) as e:
        crowdstrike_result_command(client, args)
    assert e.value.args[0] == "Got Error state from server: {'state': 'ERROR'}"


def test_map_dict_keys():
    orig = {'propertyName': 'propertyValue', 'a': 'b', 'x': 'y'}

    res = map_dict_keys(orig, {'a': 'c', 'x': 'z'}, True)
    assert res['c'] == 'b'
    assert res.get('.propertyName', None) is None

    res = map_dict_keys(orig, {'a': 'c', 'x': 'z'}, False)
    assert res['z'] == 'y'
    assert res['propertyName'] == 'propertyValue'


def test_bwc_file_context():
    """

    Given:
      - creating a bwc file

    When:
      - getting context

    Then:
      - Get non-file fields as well
    """

    ed_val = "Static Analysis"
    type_val = "typeval"
    sha256 = 'ee832579cffaf4079ff422a97d063c4badb02ce16ba7bb9f1f50273fd16f85af'
    context = BWCFile({"environment_description": ed_val,
                       "type": type_val}, {"type": "type1"}, False
                      , sha256=sha256,
                      dbot_score=Common.DBotScore.NONE).to_context()
    file_dict = context.popitem()[1]
    assert file_dict['type1'] == type_val
    assert file_dict['SHA256'] == sha256
    assert file_dict['environment_description'] == ed_val


def test_crowdstrike_submit_url_command_no_poll(requests_mock):
    """

       Given:
         - poll false

       When:
         - submit url

       Then:
         - get submission result without polling scan
       """
    submit_response = {
        "submission_type": "page_url",
        "job_id": "jobid",
        "submission_id": "submissionId",
        "environment_id": 100,
        "sha256": "9e37b19decf1ff7cb2b4d1617b4701006c51e175ef4c921c90e79a88eaf8c49a"
    }
    mock_call = requests_mock.post(BASE_URL + '/submit/url', json=submit_response)
    result = crowdstrike_submit_url_command(client, {'url': BASE_URL, 'environmentID': 300, 'comment': 'some comment'})
    assert result.outputs == submit_response
    assert 'environment_id' in mock_call.last_request.text
    assert 'comment' in mock_call.last_request.text


def test_crowdstrike_submit_url_command_poll(requests_mock, mocker):
    """

       Given:
         - poll true, scan result in progress

       When:
         - submit url

       Then:
         - submission result returned and polling scan result
       """
    submit_response = util_load_json("test_data/submission_response.json")
    mocker.patch.object(demisto, 'results')
    submit_call = requests_mock.post(BASE_URL + '/submit/url', json=submit_response)
    search_call = requests_mock.post(BASE_URL + '/search/hashes', json=[])
    state_call = requests_mock.get(BASE_URL + f"/report/12345/state", json={'state': 'IN_PROGRESS'})

    result = crowdstrike_submit_url_command(client, {'url': BASE_URL, 'environmentID': 300, 'comment': 'some comment',
                                                     "Polling": True})
    assert demisto.results.call_args.args[0]['Contents'] == submit_response
    assert result.scheduled_command is not None
