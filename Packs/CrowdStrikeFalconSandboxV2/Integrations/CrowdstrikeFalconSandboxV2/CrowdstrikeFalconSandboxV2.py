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
import urllib.parse

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

SEARCH_TERM_QUERY_ARGS = ('filename', 'filetype', 'filetype_desc', 'env_id', 'country', 'verdict', 'av_detect',
                          'vx_family', 'tag', 'date_from', 'date_to', 'port', 'host', 'domain', 'url', 'similar_to',
                          'context', 'imp_hash', 'ssdeep', 'authentihash')
# envid repeated for bw compatibility. Must be in this order so old overrides new default
SUBMISSION_PARAMETERS = {'environmentID', 'environmentId', 'no_share_third_party', 'allow_community_access',
                         'no_hash_lookup',
                         'action_script', 'hybrid_analysis', 'experimental_anti_evasion', 'script_logging',
                         'input_sample_tampering', 'network_settings', 'email', 'comment', 'custom_cmd_line',
                         'custom_run_time', 'submit_name', 'priority', 'document_password', 'environment_variable',
                         }
INTEGRATION_RELIABILITY = 'C - Fairly reliable'


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

    def submit_url(self, url, params: Dict[str, Any]):
        return self._http_request(method='POST', data={'url': url, **params},
                                  url_suffix='/submit/url')

    def submit_file(self, file_contents, params: Dict[str, Any]):
        return self._http_request(method='POST', data=params, url_suffix='/submit/file', files=
        {'file': (file_contents['name'], open(file_contents["path"], 'rb'))})

    def download_sample(self, sha256hash):
        return self._http_request(method='GET', url_suffix=f'/overview/{sha256hash}/sample', resp_type="response")


# for BW compatibility with v1 we need to return same object keys
def map_dict_keys(obj: Dict, maprules: Dict[str, str], only_given_fields=False):
    return {maprules.get(key, key): obj[key] for key in obj.keys() if not only_given_fields or key in maprules}


def translate_verdict(param: str):
    return {
        'Whitelisted': 1,
        'NoVerdict': 2,
        'NoSpecificThreat': 3,
        'Suspicious': 4,
        'Malicious': 5  # TODO different than v1 but acc to docs...
    }[param]


def split_query_to_term_args(query: str) -> Dict[str, Any]:
    def get_value(term):
        return term[term.index(':') + 1:].strip()

    def get_key(term):
        return term[:term.index(':')].strip()

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


def get_api_id(args):
    if args.get('file') and (args.get('environmentID') or args.get('environmentId')):  # backwards compatibility
        return f"{args['file']}:{args.get('environmentId') or args.get('environmentID')}"  # must be this order to override defaults
    elif args.get('JobID'):
        return args['JobID']
    else:
        raise ValueError('Must supply JobID or environmentID and file')


def test_module(client: Client, _) -> str:
    """Tests API connectivity and authentication'
    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.get_environments()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def poll(name: str, interval: int = 30, timeout: int = 600,
         poll_message: str = 'Fetching Results:'):  # todo move to base?
    """To use on a function that should rerun itself
    Commands that use this decorator must have a Polling argument, polling: true in yaml,
    and a hidden polled_once argument.
    Commands that use this decorator should return a tuple. Arg1 should be a boolean or a function that returns a boolean
    as to whether or not it should continue to poll. Arg2 should be CommandRTesults in case of success,
    or error CommandResults in case of Polling=false
    ----------
    name : str
        The name of the command
    interval : int
        How many seconds until the next run
    timeout : int
        How long
    Raises
    ------
    DemistoException
        If the server version doesnt support Scheduled Commands (< 6.2.0)
    """

    def dec(func):
        def inner(client, args) -> CommandResults:
            if args.get('Polling'):
                ScheduledCommand.raise_error_if_not_supported()
                continue_poll_provider, result = func(client, args)
                should_poll = continue_poll_provider if isinstance(continue_poll_provider, bool) \
                    else continue_poll_provider()
                if not should_poll:
                    return result
                polling_args = args
                return CommandResults(readable_output=poll_message if not args.get('polled_once') else None,
                                      scheduled_command=ScheduledCommand(command=name, next_run_in_seconds=interval,
                                                                         args={**polling_args, 'polled_once': True},
                                                                         timeout_in_seconds=timeout))
            else:
                return func(client, args)[1]

        return inner

    return dec


def get_default_file_name(fileype):
    return f"CrowdStrike_report_{round(time.time())}.{get_file_suffix(fileype)}"


def get_file_suffix(filetype='bin'):
    if filetype in ('pcap', 'bin', 'xml', 'html'):
        return 'gz'
    if filetype == 'json':
        return 'json'
    if filetype in ('misp', 'stix'):
        return 'xml'
    return filetype


def has_error_state(client, key):
    state = client.get_state(key)
    demisto.debug(f'state to check if should poll response: {state}')
    if state['state'] == 'ERROR':
        raise Exception(f'Got Error state from server: {state}')
    return False


class BWCFile(Common.File):
    def __init__(self, bwc_fields: Dict, key_change_map: Dict, only_given_fields, *args, **kwargs):
        super(BWCFile, self).__init__(*args, **kwargs)
        self.bwc_fields = bwc_fields
        self.key_change_map = key_change_map
        self.only_given_fields = only_given_fields

    def to_context(self):
        super_ret = super().to_context()
        for key in super_ret.keys():
            if key.startswith("File"):
                super_ret[key].update(map_dict_keys(self.bwc_fields, self.key_change_map, self.only_given_fields))
        return super_ret


def create_scan_results_readable_output(scan_response):
    table_field_dict = {
        'submit_name': 'submit name',
        'threat_level': 'threat level',
        'threat_score': 'threat score',
        'verdict': 'verdict',
        'total_network_connections': 'total network connections',
        'target_url': 'target url',
        'classification_tags': 'classification tags',
        'total_processes': 'total processes',
        'environment_description': 'environment description',
        'interesting': 'interesting',
        'environment_id': 'environment id',
        'url_analysis': 'url analysis',
        'analysis_start_time': 'analysis start time',
        'total_signatures': 'total signatures',
        'type': 'type',
        'type_short': 'type short',
        'vx_family': 'Malware Family',
        'sha256': 'sha256'

    }
    return tableToMarkdown('Scan Results:', scan_response, headers=list(table_field_dict.keys()),
                           headerTransform=lambda x: table_field_dict.get(x, x), removeNull=True)


def get_dbot_score(filehash, threat_score: int):
    def calc_score():
        return {3: 0,
                2: 3,
                1: 2,
                0: 1}.get(threat_score, 0)

    return Common.DBotScore(indicator=filehash, integration_name='CrowdStrike Falcon Sandbox V2',
                            indicator_type=DBotScoreType.FILE, score=calc_score(),
                            malicious_description=f'Score of {calc_score()}',
                            reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(
                                INTEGRATION_RELIABILITY))


def get_submission_arguments(args) -> Dict[str, Any]:
    return {camel_case_to_underscore(arg): args[arg] for arg in SUBMISSION_PARAMETERS if args.get(arg)}


def submission_response(client, response, polling):
    submission_res = CommandResults(outputs_prefix='CrowdStrike', outputs_key_field='submission_id',
                                    raw_response=response, outputs={'Submit': response, 'JobID': response['job_id'],
                                                                    'EnvironmentID': response['environment_id']},
                                    readable_output=
                                    tableToMarkdown("Submission Data:", response, headerTransform=underscore_to_space))

    if not polling:
        return submission_res
    else:
        return_results(submission_res)  # return early
    return crowdstrike_scan_command(client, {'file': response['sha256'], 'JobID': response['job_id'],
                                             "Polling": True})


def crowdstrike_submit_url_command(client: Client, args):
    submission_args = get_submission_arguments(args)
    url = args['url']
    response = client.submit_url(url, submission_args)
    return submission_response(client, response, args.get('Polling'))


def crowdstrike_submit_sample_command(client: Client, args):
    file_contents = demisto.getFilePath(args['entryId'])
    # TODO is this a generic error when not found? Seems obscure. Add try except?
    submission_args = get_submission_arguments(args)
    response = client.submit_file(file_contents, submission_args)
    return submission_response(client, response, args.get('Polling'))


def crowdstrike_analysis_overview_command(client: Client, args):
    result = client.analysis_overview(args['file'])
    file = Common.File(Common.DBotScore.NONE, sha256=result['sha256'], size=result['size'], file_type=result['type'],
                       name=result['last_file_name'])

    table_cols = ["last_file_name", "threat_score", "other_file_name", 'sha256', "verdict", "url_analysis", 'size',
                  'type', 'type_short']

    return CommandResults(
        outputs_prefix='CrowdStrike.AnalysisOverview',
        outputs_key_field='sha256',
        outputs=result,
        raw_response=result,
        indicator=file,
        readable_output=tableToMarkdown("Analysis Overview:", result, headers=table_cols,
                                        headerTransform=underscore_to_space,
                                        removeNull=True)
    )


def crowdstrike_search_command(client: Client, args):
    query_args: Dict = get_search_term_args(args)
    query_args = validated_search_terms(query_args)
    response = client.search(query_args)

    key_name_changes = {'job_id': 'JobID',
                        'sha256': 'SHA256',
                        'environment_id': 'environmentId',
                        'threat_score': 'threatscore',
                        'environment_description': 'environmentDescription',
                        'submit_name': 'submitname',
                        'analysis_start_time': 'start_time'}

    def convert_to_file_res(res):
        return BWCFile(res, key_name_changes, False, size=res['size'], sha256=res['sha256'],
                       dbot_score=Common.DBotScore.NONE,
                       extension=res['type_short'], name=res['submit_name'], malware_family=res['vx_family'])

    return CommandResults(
        raw_response=response,
        outputs_prefix='CrowdStrike.Search',
        outputs_key_field='sha256',
        outputs=response['result'],
        indicators=[convert_to_file_res(res) for res in response['result']],
        readable_output=tableToMarkdown("Search Results:", response['result'],
                                        ['submit_name', 'verdict', 'vx_family', 'threat_score', 'sha256', 'size',
                                         'environment_id', 'type', 'type_short', 'analysis_start_time'],
                                        removeNull=True, headerTransform=underscore_to_space)
    )


@poll('cs-falcon-sandbox-scan')
def crowdstrike_scan_command(client: Client, args):
    hashes = args['file'].split(',')
    scan_response = client.scan(hashes)

    def file_with_bwc_fields(res):
        file = BWCFile(res, {
            'sha1': 'SHA1',
            'sha256': 'SHA256',
            'md5': 'MD5',
            'job_id': 'JobID',
            'environment_id': 'environmentId',
            'threat_score': 'threatscore',
            'environment_description': 'environmentDescription',
            'submit_name': 'submitname',
            'url_analysis': 'isurlanalysis',
            'interesting:': 'isinteresting',
            'vx_family': 'family'}, False, size=res['size'], file_type=res['type'], sha1=res['sha1'],
                       sha256=res['sha256'],
                       md5=res['md5'],
                       sha512=res['sha512'], name=res['submit_name'], ssdeep=res['ssdeep'],
                       malware_family=res['vx_family'],
                       dbot_score=get_dbot_score(res['sha256'], res['threat_level']))

        return file

    files = [file_with_bwc_fields(res) for res in scan_response]

    command_result = CommandResults(outputs_prefix='CrowdStrike.Report', indicators=files,
                                    raw_response=scan_response, outputs=scan_response,
                                    readable_output=create_scan_results_readable_output(scan_response))
    if len(scan_response) != 0:
        return False, command_result
    try:
        if len(hashes) == 1:
            key = get_api_id(args)
            return lambda: not has_error_state(client, key), command_result
    except ValueError:
        demisto.debug(f'Cannot get a key to check state for {hashes}')
    return True, command_result


def crowdstrike_analysis_overview_summary_command(client: Client, args):
    result = client.analysis_overview_summary(args['file'])
    return CommandResults(
        outputs_prefix='CrowdStrike.AnalysisOverviewSummary',
        outputs_key_field='sha256',
        outputs=result,
        raw_response=result,
        readable_output=tableToMarkdown('Analysis Overview Summary:', result, headerTransform=
        lambda x: {'analysis_start_time': 'Analysis Start Time',
                   'last_multi_scan': 'Last Multi Scan',
                   'multiscan_result': 'Multiscan Result',
                   'threat_score': 'Threat Score',
                   'verdict': 'Verdict',
                   'sha256': 'Sha256'

                   }.get(x, x), removeNull=True)

    )


def crowdstrike_analysis_overview_refresh_command(client: Client, args):
    client.analysis_overview_refresh(args['file'])
    return CommandResults(readable_output='Successful')


@poll('cs-falcon-sandbox-result')
def crowdstrike_result_command(client: Client, args: Dict[str, Any]) -> (bool, CommandResults):
    key = get_api_id(args)
    report_response = client.get_report(key, args['file-type'])
    demisto.debug(f'get report response code: {report_response.status_code}')
    successful_response = report_response.status_code == 200

    if successful_response:
        ret_list = [fileResult(get_default_file_name(args['file-type']), report_response.content,
                               file_type=EntryType.ENTRY_INFO_FILE)]
        if args.get('file'):
            ret_list.append(crowdstrike_scan_command(client, args))
        return False, ret_list

    else:
        error_response = CommandResults(raw_response=report_response,
                                        readable_output="Falcon Sandbox returned an error: status code " +
                                                        f"{report_response.status_code}, response: {report_response.text}",
                                        entry_type=entryTypes['error'])

        return lambda: not has_error_state(client, key), error_response


def underscore_to_space(x: str):
    return pascalToSpace(underscoreToCamelCase(x))  # todo make better implementation in base?


def crowdstrike_report_state_command(client: Client, args):
    key = get_api_id(args)
    state = client.get_state(key)
    return CommandResults(outputs_prefix="Crowdstrike.State",raw_response=state, outputs=state,
                          readable_output=tableToMarkdown("State", state, headerTransform=underscore_to_space))


def crowdstrike_get_environments_command(client: Client, _):
    environments = client.get_environments()
    environments = [map_dict_keys(env, {'environment_id': 'ID', 'total_virtual_machines': 'VMs_total',
                                        'analysis_mode': 'analysisMode', 'group_icon': 'groupicon',
                                        'busy_virtual_machines': 'VMs_busy'}) for env in environments]

    readable_output_column_conversion = {
        'ID': '_ID', 'description': 'Description', 'architecture': 'Architecture',
        'VMs_total': 'Total VMS', 'VMs_busy': 'Busy VMS', 'analysisMode': 'Analysis mode',
        'groupicon': 'Group icon'
    }
    return CommandResults(
        outputs_prefix='CrowdStrike.Environment',
        outputs_key_field='id',
        outputs=environments,
        readable_output=tableToMarkdown('All Environments:',
                                        environments, list(readable_output_column_conversion.keys()), removeNull=True,
                                        headerTransform=lambda x: readable_output_column_conversion[x]),
        raw_response=environments
    )


def crowdstrike_get_screenshots_command(client: Client, args: Dict[str, Any]):
    def to_image_result(image):
        return fileResult(image['name'], base64.b64decode(image['image']), entryTypes['entryInfoFile'])

    key = get_api_id(args)
    return [to_image_result(image) for image in client.get_screenshots(key)]


def crowdstrike_sample_download_command(client: Client, args):
    hash_value = args['file']
    response = client.download_sample(hash_value)

    command_results = CommandResults(
        readable_output=f"Requested sample is available for download under the name {hash_value}.gz"
    )
    return [command_results, fileResult(hash_value + '.gz', data=response.content, file_type=EntryType.FILE)]


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    demisto.getIntegrationContext()
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    global INTEGRATION_RELIABILITY
    INTEGRATION_RELIABILITY = params.get("integrationReliability")
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
            crowdstrike_analysis_overview_refresh_command: ['cs-falcon-sandbox-analysis-overview-refresh'],
            crowdstrike_submit_sample_command: ['crowdstrike-submit-sample', 'cs-falcon-sandbox-submit-sample'],
            crowdstrike_submit_url_command: ['cs-falcon-sandbox-submit-url', 'crowdstrike-submit-url'],
            crowdstrike_sample_download_command: ['cs-falcon-sandbox-sample-download'],
            crowdstrike_report_state_command: ['cs-falcon-sandbox-report-state']
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

# if __name__ in ('__main__', '__builtin__', 'builtins'):
main()
