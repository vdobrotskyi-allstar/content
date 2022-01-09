"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
SEARCH_TERM_QUERY_ARGS = ('filename', 'filetype', 'filetype_desc', 'env_id', 'country', 'verdict', 'av_detect',
                          'vx_family', 'tag', 'date_from', 'date_to', 'port', 'host', 'domain', 'url', 'similiar_to',
                          'context', 'imp_hash', 'ssdeep', 'authentihash')


class Client(BaseClient):

    def get_environments(self):
        return self._http_request(method='GET', url_suffix='/system/environments')

    def get_screenshots(self, key):
        return self._http_request(method='GET', url_suffix=f"/report/{key}/screenshots")

    def search(self, query_args: Dict[str, Any]):
        self._headers['Content-Type'] = "application/x-www-form-urlencoded"
        return self._http_request(method='POST', url_suffix=f'/search/terms', data=query_args)

    def scan(self, files: List[str]):
        self._headers['Content-Type'] = "application/x-www-form-urlencoded"
        return self._http_request(method='POST', url_suffix='/search/hashes', data={'hashes[]': files})

    def analysis_overview(self, sha256hash):
        return self._http_request(method='GET', url_suffix=f'/overview/{sha256hash}')

    def analysis_overview_summary(self, sha256hash):
        return self._http_request(method='GET', url_suffix=f'/overview/{sha256hash}/summary')

    def analysis_overview_refresh(self, sha256hash):
        self._http_request(method='GET', url_suffix=f'/overview/{sha256hash}/refresh')

    def get_report(self, key, filetype):
        return self._http_request(method='GET', url_suffix=f'/report/{key}/report/{filetype}', resp_type='all',
                                  ok_codes=(200, 404))

    def get_state(self, key):
        return self._http_request(method='GET', url_suffix=f'/report/{key}/state')


def map_object(obj: Any, maprules: Dict[str, str], only_given_fields=False):
    # class InlineClass(object):
    #     def __init__(self, dict):
    #         self.__dict__ = dict
    #
    # obj = InlineClass({'propertyName': 'propertyValue'})
    return type('obj', (object,),
                {maprules.get(key, key): obj.__dict__[key]
                 for key in obj.__dict__.keys() if not only_given_fields or key in maprules})


def translate_verdict(param: str):
    return {
        'Whitelisted': 1,
        'NoVerdict': 2,
        'NoSpecificThreat': 3,
        'Suspicious': 4,
        'Malicious': 4
    }[param]


def split_query_to_term_args(query: str) -> Dict[str, Any]:
    def get_value(term):
        return term[term.index(':') + 1:]

    def get_key(term):
        return term[:term.index(':')]

    return {get_key(term): get_value(term) for term in query.split(',') if get_value(term)}


def validated_term(key, val):
    if key == 'verdict':
        return translate_verdict(val)
    if key == 'country' and len(val) != 3:
        raise ValueError('Country ISO code should be 3 characters long')
    return val


def validated_search_terms(query_args: Dict[str, Any]) -> Dict[str, Any]:
    if len(query_args) == 0:
        raise ValueError('Must have at least one search term')
    return {key: validated_term(key, query_args[key]) for key in query_args}


def get_search_term_args(args) -> Dict[str, Any]:
    if args.get('query'):
        return split_query_to_term_args(args['query'])
    else:
        return {term: args[term] for term in SEARCH_TERM_QUERY_ARGS if args.get(term, None)}


def to_image_result(image):
    return fileResult(image['name'], base64.b64decode(image['image']), entryTypes['entryInfoFile'])


def get_api_id(args):
    if args.get('file') and args.get('environmentID'):
        return f"{args['file']}:{args['environmentID']}"
    elif args.get('JobID'):
        return args['JobID']
    else:
        raise ValueError('Must supply JobID or environmentID and file')


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def crowdstrike_get_environments_command(client: Client, _):
    environments = client.get_environments()
    demisto.info(environments)
    return CommandResults(
        outputs_prefix='CrowdStrike.Environment',
        outputs_key_field='id',
        outputs=environments,
        readable_output=tableToMarkdown('All Environments:', environments, ['id', 'description'], removeNull=True,
                                        headerTransform=lambda x: {'id': '_ID', 'description': 'Description'}[x]),
        raw_response=environments
    )


def crowdstrike_get_screenshots_command(client: Client, args: Dict[str, Any]):
    key = get_api_id(args)
    return [to_image_result(image) for image in client.get_screenshots(key)]


def poll(name, interval=30, timeout=600):
    """Using this, the first argument is a bool whether or not the method has finished, the second argument is the
    finished result, or the result we want to be shown in case polling is False"""

    def dec(func):
        def inner(client, args):
            demisto.debug('args:' + str(args))
            if args.get('Polling'):
                ScheduledCommand.raise_error_if_not_supported()
                continue_poll, result = func(client, args)
                if not continue_poll:
                    return result
                polling_args = args
                return CommandResults(readable_output='Fetching Results:',
                                      scheduled_command=ScheduledCommand(command=name, next_run_in_seconds=interval,
                                                                         args={**polling_args},
                                                                         timeout_in_seconds=timeout))
            else:
                return func(client, args)[1]

        return inner

    return dec


@poll('crowdstrike-result', 11, 60)  # todo return not dep method
def crowdstrike_result_command(client: Client, args: Dict[str, Any]) -> (bool, CommandResults):
    key = get_api_id(args)
    report_response = client.get_report(key, args['file-type'])
    demisto.debug(f'get report response code: {report_response.status_code}')
    successful_response = report_response.status_code == 200

    if successful_response:
        ret_list = [fileResult('filename.txt', report_response.content, file_type=entryTypes['entryInfoFile'])]
        if args.get('file'):
            ret_list.append(crowdstrike_scan_command(client, args))
        return False, ret_list

    else:
        error_response = CommandResults(raw_response=report_response,
                                        readable_output="Falcon Sandbox returned an error: status code " +
                                                        f"{report_response.status_code}, response: {report_response.text}",
                                        entry_type=entryTypes['error'])

        if args.get('Polling'):  # extra fetch if we dont poll
            state = client.get_state(key)
            demisto.results(f'state check: {state}')
            demisto.debug(f'state to check if should poll response: {state}')
            return state['state'] != 'ERROR', error_response

        return False, error_response


def crowdstrike_search_command(client: Client, args):
    query_args: Dict = get_search_term_args(args)
    query_args = validated_search_terms(query_args)
    response = client.search(query_args)

    def convert_to_file_res(res):
        return Common.File(size=res['size'], sha256=res['sha256'], dbot_score=get_dbot_score(res['sha256']
                                                                                             , res['threat_score']),
                           extension=res['type_short'], name=res['submit_name'])

    return CommandResults(
        raw_response=response,
        outputs_prefix='CrowdStrike.Search',
        outputs=response['result'],
        indicators=[convert_to_file_res(res) for res in response['result']]
    )


@poll('cs-falcon-sandbox-scan', 20, 60)
def crowdstrike_scan_command(client: Client, args):
    scan_response = client.scan(args['file'].split(','))
    files = [Common.File(size=res['size'], file_type = res['type'], sha1=res['sha1'], sha256=res['sha256'],
                         sha512=res['sha512'],name=res['submit_name'], ssdeep=res['ssdeep'], dbot_score=get_dbot_score(res['sha256'],res['threat_score'])) for res in scan_response]
    command_result = CommandResults(outputs_prefix='CrowdStrike.Report', indicators=files,
                                    raw_response=scan_response, outputs=scan_response)
    return False, command_result  # TODO check if empty


def get_dbot_score(filehash, raw_score: int):
    def calc_score():
        return {3: 0,
                2: 3,
                1: 2,
                0: 1}.get(raw_score, 0)

    return Common.DBotScore(indicator=filehash, integration_name='CrowdStrike Falcon Sandbox V2',
                            indicator_type=DBotScoreType.FILE, score=calc_score())


def crowdstrike_analysis_overview_command(client: Client, args):
    result = client.analysis_overview(args['file'])
    file = Common.File(sha256=result['sha256'], size=result['size'], file_type=result['type'],
                       dbot_score=get_dbot_score(args['file'], result['threat_score']))
    return CommandResults(
        outputs_prefix='CrowdStrike.AnalysisOverview',
        outputs_key_field='sha256',
        outputs=result,
        raw_response=result,
        indicator=file
        # TODO what should be human readable
    )


def crowdstrike_analysis_overview_summary_command(client: Client, args):
    result = client.analysis_overview_summary(args['file'])
    return CommandResults(
        outputs_prefix='CrowdStrike.AnalysisOverviewSummary',
        outputs_key_field='sha256',
        outputs=result,
        raw_response=result,
        readable_output=tableToMarkdown('Analysis Overview Summary:', result, removeNull=True)

    )


def crowdstrike_analysis_overview_refresh(client: Client, args):
    client.analysis_overview_refresh(args['file'])
    return CommandResults(readable_output='Successful')


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: Dict = {
            'api-key': demisto.params().get('credentials', {}).get('password'),
            'User-Agent': 'Falcon Sandbox'
        }

        client = Client(
            base_url=demisto.params()['serverUrl'],
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        backwards_dictionary = {
            test_module: ['test-module'],
            crowdstrike_search_command: ['cs-falcon-sandbox-search', 'crowdstrike-search'],
            crowdstrike_scan_command: ['cs-falcon-sandbox-scan', 'crowdstrike-scan', 'file'],
            crowdstrike_get_environments_command: ['crowdstrike-get-environments',
                                                   'cs-falcon-sandbox-get-environments'],
            crowdstrike_get_screenshots_command: ['cs-falcon-sandbox-get-screenshots', 'crowdstrike-get-screenshots'],
            crowdstrike_result_command: ['cs-falcon-sandbox-result', 'crowdstrike-result'],
            crowdstrike_analysis_overview_command: ['cs-falcon-sandbox-analysis-overview'],
            crowdstrike_analysis_overview_summary_command: ['cs-falcon-sandbox-analysis-overview-summary'],
            crowdstrike_analysis_overview_refresh: ['cs-falcon-sandbox-analysis-overview-refresh']
        }
        commands_dict = {}
        for command in backwards_dictionary:
            for command_text in backwards_dictionary[command]:
                commands_dict[command_text] = command
        return_results(commands_dict[demisto.command()](client, args))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

# if __name__ in ('__main__', '__builtin__', 'builtins'): #TODO put me back
main()
