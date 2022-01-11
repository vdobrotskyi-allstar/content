"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io

from Packs.CrowdStrikeFalconSandboxV2.Integrations.CrowdstrikeFalconSandboxV2.CrowdstrikeFalconSandboxV2 import \
    validated_search_terms, split_query_to_term_args, map_dict_keys


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


# # TODO: REMOVE the following dummy unit test function
# def test_baseintegration_dummy():
#     """Tests helloworld-say-hello command function.
#
#     Checks the output of the command function with the expected output.
#
#     No mock is needed here because the say_hello_command does not call
#     any external API.
#     """
#     from BaseIntegration import Client, baseintegration_dummy_command
#
#     client = Client(base_url='some_mock_url', verify=False)
#     args = {
#         'dummy': 'this is a dummy response'
#     }
#     response = baseintegration_dummy_command(client, args)
#
#     mock_response = util_load_json('test_data/baseintegration-dummy.json')
#
#     assert response.outputs == mock_response
# # TODO: ADD HERE unit tests for every command
def test_validated_search_terms():
    pre_validation = {"hello": "world", "verdict": 'NoSpecificThreat'}
    post_validation = validated_search_terms(pre_validation)
    assert post_validation == {'hello': 'world', 'verdict': 3}


def test_split_query_to_term_args():
    query = 'hello:world,three:split:fine,heelo:'
    res = split_query_to_term_args(query)
    assert {'hello': 'world', 'three': 'split:fine'} == res


def test_map_dict_keys():
    orig = {'propertyName': 'propertyValue', 'a': 'b', 'x': 'y'}

    res = map_dict_keys(orig, {'a': 'c', 'x': 'z'}, True)
    assert res['c'] == 'b'
    assert res.get('.propertyName', None) is None

    res = map_dict_keys(orig, {'a': 'c', 'x': 'z'}, False)
    assert res['z'] == 'y'
    assert res['propertyName'] == 'propertyValue'
