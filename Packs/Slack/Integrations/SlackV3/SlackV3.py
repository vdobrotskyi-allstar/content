import asyncio
import concurrent
import ssl
import threading
from distutils.util import strtobool
from typing import Tuple

import aiohttp
import slack_sdk
from slack_sdk.errors import SlackApiError
from slack_sdk.socket_mode.aiohttp import SocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.web.slack_response import SlackResponse

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa


async def get_file(self: AsyncWebClient, url_private: str):
    demisto.debug(f'download url is {url_private=}')
    res = requests.get(url_private, headers={'Authorization': f'Bearer {self.token}'}, verify=False)  # TODO: verify from params.
    demisto.debug(f'{url_private} {res.status_code=}')
    return res.content

''' CONSTANTS '''

SEVERITY_DICT = {
    'Unknown': 0,
    'Low': 1,
    'Medium': 2,
    'High': 3,
    'Critical': 4
}

USER_TAG_EXPRESSION = '<@(.*?)>'
CHANNEL_TAG_EXPRESSION = '<#(.*?)>'
URL_EXPRESSION = r'<(https?://.+?)(?:\|.+)?>'
GUID_REGEX = r'(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}'
ENTITLEMENT_REGEX = r'{}@(({})|(?:[\d_]+))_*(\|\S+)?\b'.format(GUID_REGEX, GUID_REGEX)
COMMAND_REGEX = r"command.*?(?=;)"
MESSAGE_FOOTER = '\n**From Slack**'
MIRROR_TYPE = 'mirrorEntry'
INCIDENT_OPENED = 'incidentOpened'
INCIDENT_NOTIFICATION_CHANNEL = 'incidentNotificationChannel'
PLAYGROUND_INVESTIGATION_TYPE = 9
WARNING_ENTRY_TYPE = 11
POLL_INTERVAL_MINUTES: Dict[Tuple, float] = {
    (0, 15): 1,
    (15, 60): 2,
    (60,): 5
}
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
OBJECTS_TO_KEYS = {
    'mirrors': 'investigation_id',
    'questions': 'entitlement',
    'users': 'id'
}
SYNC_CONTEXT = True

''' GLOBALS '''

BOT_TOKEN: str
APP_TOKEN: str
PROXY_URL: Optional[str]
PROXIES: dict
DEDICATED_CHANNEL: str
ASYNC_CLIENT: slack_sdk.web.async_client.AsyncWebClient
# Add the files_get method
CLIENT: slack_sdk.WebClient
ALLOW_INCIDENTS: bool
INCIDENT_TYPE: str
SEVERITY_THRESHOLD: int
VERIFY_CERT: bool
SSL_CONTEXT: Optional[ssl.SSLContext]
QUESTION_LIFETIME: int
BOT_NAME: str
BOT_ICON_URL: str
MAX_LIMIT_TIME: int
PAGINATED_COUNT: int
ENABLE_DM: bool
PERMITTED_NOTIFICATION_TYPES: List[str]


''' HELPER FUNCTIONS '''


def is_bot_message(message, bot_id=None):
    if not bot_id:
        bot_id = get_bot_id()


def get_bot_id() -> str:
    """
    Gets the app bot ID

    Returns:
        The app bot ID
    """
    response = CLIENT.auth_test()
    return response.get('user_id')


def test_module():
    """
    Sends a test message to the dedicated slack channel.
    """
    if not DEDICATED_CHANNEL and len(PERMITTED_NOTIFICATION_TYPES) > 0:
        return_error(
            "When 'Types of Notifications to Send' is populated, a dedicated channel is required.")
    elif not DEDICATED_CHANNEL and len(PERMITTED_NOTIFICATION_TYPES) == 0:
        CLIENT.auth_test()  # type: ignore
    else:
        channel = get_conversation_by_name(DEDICATED_CHANNEL)
        if not channel:
            return_error('Dedicated channel not found.')
        message = 'Hi there! This is a test message.'

        CLIENT.chat_postMessage(channel=channel.get('id'), text=message)  # type: ignore

    demisto.results('ok')


def get_current_utc_time() -> datetime:
    """
    Returns:
        The current UTC time.
    """
    return datetime.utcnow()


def get_user_by_name(user_to_search: str, add_to_context: bool = True) -> dict:
    """
    Gets a slack user by a user name

    Args:
        user_to_search: The user name or email
        add_to_context: Whether to update the integration context

    Returns:
        A slack user object
    """

    user: dict = {}
    users: list = []
    integration_context = get_integration_context(SYNC_CONTEXT)

    user_to_search = user_to_search.lower()
    if integration_context.get('users'):
        users = json.loads(integration_context['users'])
        users_filter = list(filter(lambda u: u.get('name', '').lower() == user_to_search
                                             or u.get('profile', {}).get('email', '').lower() == user_to_search
                                             or u.get('real_name', '').lower() == user_to_search, users))
        if users_filter:
            user = users_filter[0]
    if not user:
        body = {
            'limit': PAGINATED_COUNT
        }

        response = send_slack_request_sync(CLIENT, 'users.list', http_verb='GET', body=body)
        while True:
            workspace_users = response['members'] if response and response.get('members',
                                                                               []) else []
            cursor = response.get('response_metadata', {}).get('next_cursor')
            users_filter = list(filter(lambda u: u.get('name', '').lower() == user_to_search
                                       or u.get('profile', {}).get('email', '').lower() == user_to_search
                                       or u.get('real_name', '').lower() == user_to_search, workspace_users))
            if users_filter:
                break
            if not cursor:
                break
            body = body.copy()  # strictly for unit testing purposes
            body.update({'cursor': cursor})
            response = send_slack_request_sync(CLIENT, 'users.list', http_verb='GET', body=body)

        if users_filter:
            user = users_filter[0]
            if add_to_context:
                users.append(user)
                set_to_integration_context_with_retries({'users': users}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
        else:
            return {}

    return user


def search_slack_users(users: Union[list, str]) -> list:
    """
    Search given users in Slack

    Args:
        users: The users to find

    Returns:
        The slack users
    """
    slack_users = []

    if not isinstance(users, list):
        users = [users]

    for user in users:
        slack_user = get_user_by_name(user)
        if not slack_user:
            demisto.results({
                'Type': WARNING_ENTRY_TYPE,
                'Contents': f'User {user} not found in Slack',
                'ContentsFormat': formats['text']
            })
        else:
            slack_users.append(slack_user)
    return slack_users


def find_mirror_by_investigation() -> dict:
    """
    Finds a mirrored channel by the mirrored investigation

    Returns:
        The mirror object
    """
    mirror: dict = {}
    investigation = demisto.investigation()
    if investigation:
        integration_context = get_integration_context(SYNC_CONTEXT)
        if integration_context.get('mirrors'):
            mirrors = json.loads(integration_context['mirrors'])
            investigation_filter = list(filter(lambda m: investigation.get('id') == m['investigation_id'],
                                               mirrors))
            if investigation_filter:
                mirror = investigation_filter[0]

    return mirror


def set_name_and_icon(body: dict, method: str):
    """
    If provided, sets a name and an icon for the bot if a message is sent.
    Args:
        body: The message body.
        method: The current API method.
    """
    if method == 'chat.postMessage':
        if BOT_NAME:
            body['username'] = BOT_NAME
        if BOT_ICON_URL:
            body['icon_url'] = BOT_ICON_URL


def send_slack_request_sync(client: slack_sdk.WebClient, method: str, http_verb: str = 'POST', file_: str = '',
                            body: dict = None) -> SlackResponse:
    """
    Sends a request to slack API while handling rate limit errors.

    Args:
        client: The slack client.
        method: The method to use.
        http_verb: The HTTP method to use.
        file_: A file path to send.
        body: The request body.

    Returns:
        The slack API response.
    """
    if body is None:
        body = {}

    set_name_and_icon(body, method)
    total_try_time = 0
    while True:
        try:
            demisto.debug(f'Sending slack {method} (sync). Body is: {str(body)}')
            if http_verb == 'POST':
                if file_:
                    response = client.api_call(method, files={"file": file_}, data=body)
                else:
                    response = client.api_call(method, json=body)
            else:
                response = client.api_call(method, http_verb='GET', params=body)
        except SlackApiError as api_error:
            demisto.debug(f'Got rate limit error (sync). Body is: {str(body)}\n{api_error}')
            response = api_error.response
            headers = response.headers  # type: ignore
            if 'Retry-After' in headers:
                retry_after = int(headers['Retry-After'])
                total_try_time += retry_after
                if total_try_time < MAX_LIMIT_TIME:
                    time.sleep(retry_after)
                    continue
            raise
        break

    return response  # type: ignore


async def send_slack_request_async(client: AsyncWebClient, method: str, http_verb: str = 'POST', file_: str = '',
                                   body: dict = None) -> SlackResponse:
    """
    Sends an async request to slack API while handling rate limit errors.

    Args:
        client: The slack client.
        method: The method to use.
        http_verb: The HTTP method to use.
        file_: A file path to send.
        body: The request body.

    Returns:
        The slack API response.
    """
    if body is None:
        body = {}

    set_name_and_icon(body, method)
    total_try_time = 0
    while True:
        try:
            demisto.debug(f'Sending slack {method} (async). Body is: {str(body)}')
            if http_verb == 'POST':
                if file_:
                    response = await client.api_call(method, files={"file": file_}, data=body)  # type: ignore
                else:
                    response = await client.api_call(method, json=body)  # type: ignore
            else:
                response = await client.api_call(method, http_verb='GET', params=body)  # type: ignore
        except SlackApiError as api_error:
            demisto.debug(f'Got rate limit error (async). Body is: {str(body)}\n{api_error}')
            response = api_error.response
            headers = response.headers
            if 'Retry-After' in headers:
                retry_after = int(headers['Retry-After'])
                total_try_time += retry_after
                if total_try_time < MAX_LIMIT_TIME:
                    await asyncio.sleep(retry_after)
                    continue
            raise
        break

    return response  # type: ignore


''' MIRRORING '''


async def get_slack_name(slack_id: str, client: AsyncWebClient) -> str:
    """
    Get the slack name of a provided user or channel by its ID

    Args:
        client: The slack client
        slack_id: The slack user or channel ID

    Returns:
        The slack user or channel name
    """
    if not slack_id:
        return ''

    integration_context = get_integration_context(SYNC_CONTEXT)
    prefix = slack_id[0]
    slack_name = ''

    if prefix in ['C', 'D', 'G']:
        slack_id = slack_id.split('|')[0]
        conversation: dict = {}
        if integration_context.get('conversations'):
            conversations = list(filter(lambda c: c['id'] == slack_id,
                                        json.loads(integration_context['conversations'])))
            if conversations:
                conversation = conversations[0]
        if not conversation:
            conversation = await client.conversations_info(channel=slack_id)  # type: ignore
        slack_name = conversation.get('name', '')
    elif prefix == 'U':
        user: dict = {}
        if integration_context.get('users'):
            users = list(filter(lambda u: u['id'] == slack_id, json.loads(integration_context['users'])))
            if users:
                user = users[0]
        if not user:
            user = await client.users_info(user=slack_id)  # type: ignore

        slack_name = user.get('name', '')

    return slack_name


async def clean_message(message: str, client: AsyncWebClient) -> str:
    """
    Prettifies a slack message - replaces tags and URLs with clean expressions

    Args:
        message: The slack message
        client: The slack client

    Returns:
        The clean slack message
    """
    matches = re.findall(USER_TAG_EXPRESSION, message)
    matches += re.findall(CHANNEL_TAG_EXPRESSION, message)
    message = re.sub(USER_TAG_EXPRESSION, r'\1', message)
    message = re.sub(CHANNEL_TAG_EXPRESSION, r'\1', message)
    for match in matches:
        slack_name = await get_slack_name(match, client)
        message = message.replace(match, slack_name)

    resolved_message = re.sub(URL_EXPRESSION, r'\1', message)

    return resolved_message


def invite_users_to_conversation(conversation_id: str, users_to_invite: list):
    """
    Invites users to a provided conversation using a provided slack client with a channel token.

    Args:
        conversation_id: The slack conversation ID to invite the users to.
        users_to_invite: The user slack IDs to invite.
    """
    for user in users_to_invite:
        try:
            body = {
                'channel': conversation_id,
                'users': user
            }
            send_slack_request_sync(CLIENT, 'conversations.invite', body=body)

        except SlackApiError as e:
            message = str(e)
            if "already_in_channel" in message:
                continue
            elif message.find('cant_invite_self') == -1:
                raise


def kick_users_from_conversation(conversation_id: str, users_to_kick: list):
    """
    Kicks users from a provided conversation using a provided slack client with a channel token.

    Args:
        conversation_id: The slack conversation ID to kick the users from.
        users_to_kick: The user slack IDs to kick.
    """
    for user in users_to_kick:
        try:
            body = {
                'channel': conversation_id,
                'user': user
            }
            send_slack_request_sync(CLIENT, 'conversations.kick', body=body)
        except SlackApiError as e:
            message = str(e)
            if message.find('cant_invite_self') == -1:
                raise


def mirror_investigation():
    """
    Updates the integration context with a new or existing mirror.
    """
    mirror_type = demisto.args().get('type', 'all')
    auto_close = demisto.args().get('autoclose', 'true')
    mirror_direction = demisto.args().get('direction', 'both')
    mirror_to = demisto.args().get('mirrorTo', 'group')
    channel_name = demisto.args().get('channelName', '')
    channel_topic = demisto.args().get('channelTopic', '')
    kick_admin = bool(strtobool(demisto.args().get('kickAdmin', 'false')))

    investigation = demisto.investigation()

    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        return_error('Can not perform this action in playground.')

    integration_context = get_integration_context(SYNC_CONTEXT)

    if not integration_context or not integration_context.get('mirrors', []):
        mirrors: list = []
    else:
        mirrors = json.loads(integration_context['mirrors'])
    if not integration_context or not integration_context.get('conversations', []):
        conversations: list = []
    else:
        conversations = json.loads(integration_context['conversations'])

    investigation_id = investigation.get('id')
    send_first_message = False
    current_mirror = list(filter(lambda m: m['investigation_id'] == investigation_id, mirrors))
    channel_filter: list = []
    if channel_name:
        channel_filter = list(filter(lambda m: m['channel_name'] == channel_name, mirrors))
    if not current_mirror:
        channel_name = channel_name or f'incident-{investigation_id}'

        if not channel_filter:
            body = {
                'name': channel_name
            }

            if mirror_to != 'channel':
                body['is_private'] = True

            conversation = send_slack_request_sync(CLIENT, 'conversations.create',
                                                   body=body).get('channel', {})
            conversation_name = conversation.get('name')
            conversation_id = conversation.get('id')
            conversations.append(conversation)

            # Get the bot ID so we can invite him
            if integration_context.get('bot_id'):
                bot_id = integration_context['bot_id']
            else:
                bot_id = get_bot_id()
                set_to_integration_context_with_retries({'bot_id': bot_id}, OBJECTS_TO_KEYS, SYNC_CONTEXT)

            invite_users_to_conversation(conversation_id, [bot_id])

            send_first_message = True
        else:
            mirrored_channel = channel_filter[0]
            conversation_id = mirrored_channel['channel_id']
            conversation_name = mirrored_channel['channel_name']

        mirror = {
            'channel_id': conversation_id,
            'channel_name': conversation_name,
            'investigation_id': investigation.get('id'),
            'mirror_type': mirror_type,
            'mirror_direction': mirror_direction,
            'mirror_to': mirror_to,
            'auto_close': bool(strtobool(auto_close)),
            'mirrored': False
        }

    else:
        mirror = mirrors.pop(mirrors.index(current_mirror[0]))
        conversation_id = mirror['channel_id']
        if mirror_type:
            mirror['mirror_type'] = mirror_type
        if auto_close:
            mirror['auto_close'] = bool(strtobool(auto_close))
        if mirror_direction:
            mirror['mirror_direction'] = mirror_direction
        if mirror_to and mirror['mirror_to'] != mirror_to:
            return_error('Cannot change the Slack channel type from XSOAR.')
        if channel_name:
            return_error('Cannot change the Slack channel name.')
        if channel_topic:
            return_error('Cannot change the Slack channel topic.')
        conversation_name = mirror['channel_name']
        mirror['mirrored'] = False

    set_topic = False
    if channel_topic:
        set_topic = True
    else:
        mirror_name = f'incident-{investigation_id}'
        channel_filter = list(filter(lambda m: m['channel_name'] == conversation_name, mirrors))
        if 'channel_topic' in mirror:
            channel_topic = mirror['channel_topic']
        elif channel_filter:
            channel_mirror = channel_filter[0]
            channel_topic = channel_mirror['channel_topic']
        else:
            channel_topic = ''
        mirrored_investigations_ids = list(map(lambda m: f'incident-{m["investigation_id"]}', channel_filter))
        if not channel_topic or channel_topic.find('incident-') != -1:
            new_topic = ', '.join(mirrored_investigations_ids + [mirror_name])
            if channel_topic != new_topic:
                channel_topic = new_topic
                set_topic = True

    if set_topic:
        body = {
            'channel': conversation_id,
            'topic': channel_topic
        }
        send_slack_request_sync(CLIENT, 'conversations.setTopic', body=body)
    mirror['channel_topic'] = channel_topic

    mirrors.append(mirror)

    set_to_integration_context_with_retries({'mirrors': mirrors, 'conversations': conversations}, OBJECTS_TO_KEYS,
                                            SYNC_CONTEXT)

    if kick_admin:
        body = {
            'channel': conversation_id
        }
        send_slack_request_sync(CLIENT, 'conversations.leave', body=body)
    if send_first_message:
        server_links = demisto.demistoUrls()
        server_link = server_links.get('server')
        message = (f'This channel was created to mirror incident {investigation_id}.'
                   f' \n View it on: {server_link}#/WarRoom/{investigation_id}')
        body = {
            'text': message,
            'channel': conversation_id
        }

        send_slack_request_sync(CLIENT, 'chat.postMessage', body=body)

    demisto.results(f'Investigation mirrored successfully, channel: {conversation_name}')


async def long_running_loop():
    while True:
        error = ''
        try:
            check_for_mirrors()
            check_for_unanswered_questions()
        except requests.exceptions.ConnectionError as e:
            error = f'Could not connect to the Slack endpoint: {str(e)}'
        except Exception as e:
            error = f'An error occurred: {e}'
        finally:
            demisto.updateModuleHealth('')
            if error:
                demisto.error(error)
                demisto.updateModuleHealth(error)


def get_poll_minutes(current_time: datetime, sent: Optional[str]) -> float:
    """
    Get the interval to wait before polling again in minutes.

    Args:
        current_time: The current time.
        sent: The time when the polling request was sent.

    Returns:
        Total minutes to wait before polling.
    """
    poll_time_minutes = 1.0
    if sent:
        sent_time = datetime.strptime(sent, DATE_FORMAT)
        total_delta = current_time - sent_time
        total_minutes = total_delta.total_seconds() / 60

        for minute_range, interval in POLL_INTERVAL_MINUTES.items():
            if len(minute_range) > 1 and total_minutes > minute_range[1]:
                continue
            poll_time_minutes = interval
            break

    return poll_time_minutes


def answer_question(text: str, question: dict, email: str = ''):
    entitlement = question.get('entitlement', '')
    content, guid, incident_id, task_id = extract_entitlement(entitlement, text)
    try:
        demisto.handleEntitlementForUser(incident_id, guid, email, content, task_id)
    except Exception as e:
        demisto.error(f'Failed handling entitlement {entitlement}: {str(e)}')
    question['remove'] = True


def check_for_unanswered_questions():
    integration_context = get_integration_context(SYNC_CONTEXT)
    questions = integration_context.get('questions', [])
    users = integration_context.get('users', [])
    if questions:
        questions = json.loads(questions)
    if users:
        users = json.loads(users)
    now = get_current_utc_time()
    now_string = datetime.strftime(now, DATE_FORMAT)
    updated_questions = []

    for question in questions:
        if question.get('last_poll_time'):
            if question.get('expiry'):
                # Check if the question expired - if it did, answer it with the default response
                # and remove it
                expiry = datetime.strptime(question['expiry'], DATE_FORMAT)
                if expiry < now:
                    answer_question(question.get('default_response'), question, email='')
                    updated_questions.append(question)
                    continue
            # Check if it has been enough time(determined by the POLL_INTERVAL_MINUTES parameter)
            # since the last polling time. if not, continue to the next question until it has.
            last_poll_time = datetime.strptime(question['last_poll_time'], DATE_FORMAT)
            delta = now - last_poll_time
            minutes = delta.total_seconds() / 60
            sent = question.get('sent', None)
            poll_time_minutes = get_poll_minutes(now, sent)
            if minutes < poll_time_minutes:
                continue
        entitlement = question.get('entitlement', '')
        demisto.info(f'Slack - polling for an answer for entitlement {entitlement}')
        question['last_poll_time'] = now_string
        updated_questions.append(question)
    if updated_questions:
        set_to_integration_context_with_retries({'users': users, 'questions': questions}, OBJECTS_TO_KEYS, SYNC_CONTEXT)


def check_for_mirrors():
    """
    Checks for newly created mirrors and handles the mirroring process
    """
    integration_context = get_integration_context(SYNC_CONTEXT)
    if integration_context.get('mirrors'):
        mirrors = json.loads(integration_context['mirrors'])
        updated_mirrors = []
        updated_users = []
        for mirror in mirrors:
            if not mirror['mirrored']:
                investigation_id = mirror['investigation_id']
                demisto.info(f'Mirroring: {investigation_id}')
                mirror = mirrors.pop(mirrors.index(mirror))
                if mirror['mirror_to'] and mirror['mirror_direction'] and mirror['mirror_type']:
                    mirror_type = mirror['mirror_type']
                    auto_close = mirror['auto_close']
                    direction = mirror['mirror_direction']
                    channel_id = mirror['channel_id']
                    if isinstance(auto_close, str):
                        auto_close = bool(strtobool(auto_close))
                    users: List[Dict] = demisto.mirrorInvestigation(investigation_id,
                                                                    f'{mirror_type}:{direction}', auto_close)
                    if mirror_type != 'none':
                        try:
                            invited_users = invite_to_mirrored_channel(channel_id, users)
                            updated_users.extend(invited_users)
                        except Exception as error:
                            demisto.error(f"Could not invite investigation users to the mirrored channel: {error}")

                    mirror['mirrored'] = True
                    updated_mirrors.append(mirror)
                else:
                    demisto.info(f'Could not mirror {investigation_id}')

        if updated_mirrors:
            context = {'mirrors': updated_mirrors}
            if updated_users:
                context['users'] = updated_users

            set_to_integration_context_with_retries(context, OBJECTS_TO_KEYS, SYNC_CONTEXT)
        return


def invite_to_mirrored_channel(channel_id: str, users: List[Dict]) -> list:
    """
    Invite the relevant users to a mirrored channel
    Args:
        channel_id: The mirrored channel
        users: The users to invite, each a dict of username and email

    Returns:
        users: The slack users that were invited
    """
    slack_users = []
    for user in users:
        slack_user: dict = {}
        # Try to invite by XSOAR email
        user_email = user.get('email', '')
        user_name = user.get('username', '')
        if user_email:
            slack_user = get_user_by_name(user_email, False)
        if not slack_user:
            # Try to invite by XSOAR user name
            if user_name:
                slack_user = get_user_by_name(user_name, False)
        if slack_user:
            slack_users.append(slack_user)
        else:
            demisto.results({
                'Type': WARNING_ENTRY_TYPE,
                'Contents': f'User {user_name} not found in Slack',
                'ContentsFormat': formats['text']
            })

    users_to_invite = [user.get('id') for user in slack_users]
    invite_users_to_conversation(channel_id, users_to_invite)

    return slack_users


def extract_entitlement(entitlement: str, text: str) -> Tuple[str, str, str, str]:
    """
    Extracts entitlement components from an entitlement string
    Args:
        entitlement: The entitlement itself
        text: The actual reply text

    Returns:
        Entitlement components
    """
    parts = entitlement.split('@')
    guid = parts[0]
    id_and_task = parts[1].split('|')
    incident_id = id_and_task[0]
    task_id = ''

    if len(id_and_task) > 1:
        task_id = id_and_task[1]
    content = text.replace(entitlement, '', 1)

    return content, guid, incident_id, task_id


class SlackLogger:
    """
    Slack's Socket listener by default pipes messages via stdout. This is an attempt to capture those
    and instead log them into the XSOAR server logs.

    Essentially this converts Logger.info() to demisto.info()
    """

    def __init__(self):
        """
        Set the base level as debug. The server will handle the filtering as needed.
        """
        self.level = logging.DEBUG

    @staticmethod
    def info(message):
        demisto.info(message)

    @staticmethod
    def error(message):
        demisto.error(message)

    @staticmethod
    def debug(message):
        demisto.debug(message)

    @staticmethod
    def exception(message):
        demisto.error(message)


async def slack_loop():
    while True:
        # SocketModeClient does not respect environment variables for ssl verification.
        # Instead we use a custom session.
        session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=VERIFY_CERT))
        slack_logger = SlackLogger()
        client = SocketModeClient(
            app_token=APP_TOKEN,
            web_client=ASYNC_CLIENT,
            logger=slack_logger  # type: ignore
        )
        client.aiohttp_client_session = session
        client.socket_mode_request_listeners.append(listen)  # type: ignore
        try:
            await client.connect()
            await asyncio.sleep(float("inf"))
        except Exception as e:
            await handle_listen_error(f"An error occurred {str(e)}")


async def handle_listen_error(error: str):
    """
    Logs an error and updates the module health accordingly.

    Args:
        error: The error string.
    """
    demisto.error(error)
    demisto.updateModuleHealth(error)


async def start_listening():
    """
    Starts a Slack SocketMode client and checks for mirrored incidents.
    """
    await slack_loop()
    long_loop_task = asyncio.create_task(long_running_loop(), name="Unanswered loop")
    await asyncio.gather(long_loop_task)


async def handle_dm(user: dict, text: str, client: AsyncWebClient):
    """
    Handles a direct message sent to the bot

    Args:
        user: The user who sent the message
        text: The message text
        client: The Slack client

    Returns:
        Text to return to the user
    """
    demisto.info('Slack - handling direct message.')
    message: str = text.lower()
    if message.find('incident') != -1 and (message.find('create') != -1
                                           or message.find('open') != -1
                                           or message.find('new') != -1):
        user_email = user.get('profile', {}).get('email', '')
        user_name = user.get('name', '')
        if user_email:
            demisto_user = demisto.findUser(email=user_email)
        else:
            demisto_user = demisto.findUser(username=user.get('name'))

        if not demisto_user and not ALLOW_INCIDENTS:
            data = 'You are not allowed to create incidents.'
        else:
            try:
                data = await translate_create(text, user_name, user_email, demisto_user)
            except Exception as e:
                data = f'Failed creating incidents: {str(e)}'
    else:
        try:
            data = demisto.directMessage(text, user.get('name'), user.get('profile', {}).get('email'), ALLOW_INCIDENTS)
        except Exception as e:
            data = str(e)

    if not data:
        data = 'Sorry, I could not perform the selected operation.'
    body = {
        'users': user.get('id')
    }
    im = await send_slack_request_async(client, 'conversations.open', body=body)
    channel = im.get('channel', {}).get('id')
    body = {
        'text': data,
        'channel': channel
    }

    await send_slack_request_async(client, 'chat.postMessage', body=body)


async def translate_create(message: str, user_name: str, user_email: str, demisto_user: dict) -> str:
    """
    Processes an incident creation message
    Args:
        message: The creation message
        user_name: The name of the user in Slack
        user_email: The email of the user in Slack
        demisto_user: The demisto user associated with the request (if exists)

    Returns:
        Creation result
    """
    json_pattern = r'(?<=json=).*'
    name_pattern = r'(?<=name=).*'
    type_pattern = r'(?<=type=).*'
    message = message.replace("\n", '').replace('`', '')
    json_match = re.search(json_pattern, message)
    created_incident = None
    data = ''
    user_demisto_id = ''
    if demisto_user:
        user_demisto_id = demisto_user.get('id', '')

    if json_match:
        if re.search(name_pattern, message) or re.search(type_pattern, message):
            data = 'No other properties other than json should be specified.'
        else:
            incidents_json = json_match.group()
            incidents = json.loads(incidents_json.replace('“', '"').replace('”', '"'))
            if not isinstance(incidents, list):
                incidents = [incidents]
            created_incident = await create_incidents(incidents, user_name, user_email, user_demisto_id)

            if not created_incident:
                data = 'Failed creating incidents.'
    else:
        name_match = re.search(name_pattern, message)
        if not name_match:
            data = 'Please specify arguments in the following manner: name=<name> type=[type] or json=<json>.'
        else:
            incident_name = re.sub('type=.*', '', name_match.group()).strip()
            incident_type = ''

            type_match = re.search(type_pattern, message)
            if type_match:
                incident_type = re.sub('name=.*', '', type_match.group()).strip()

            incident = {'name': incident_name}

            incident_type = incident_type or INCIDENT_TYPE
            if incident_type:
                incident['type'] = incident_type

            created_incident = await create_incidents([incident], user_name, user_email, user_demisto_id)
            if not created_incident:
                data = 'Failed creating incidents.'

    if created_incident:
        if isinstance(created_incident, list):
            created_incident = created_incident[0]
        server_links = demisto.demistoUrls()
        server_link = server_links.get('server')
        incident_name = created_incident['name']
        incident_id = created_incident['id']
        data = f'Successfully created incident {incident_name}.\n View it on: {server_link}#/WarRoom/{incident_id}'

    return data


async def create_incidents(incidents: list, user_name: str, user_email: str, user_demisto_id: str = '') -> dict:
    """
    Creates incidents according to a provided JSON object
    Args:
        incidents: The incidents JSON
        user_name The name of the user in Slack
        user_email The email of the user in Slack
        user_demisto_id: The id of demisto user associated with the request (if exists)

    Returns:
        The creation result
    """

    for incident in incidents:
        # Add relevant labels to context
        labels = incident.get('labels', [])
        keys = [label.get('type') for label in labels]
        if 'Reporter' not in keys:
            labels.append({'type': 'Reporter', 'value': user_name})
        if 'ReporterEmail' not in keys:
            labels.append({'type': 'ReporterEmail', 'value': user_email})
        if 'Source' not in keys:
            labels.append({'type': 'Source', 'value': 'Slack'})
        incident['labels'] = labels

    if user_demisto_id:
        data = demisto.createIncidents(incidents, userID=user_demisto_id)
    else:
        data = demisto.createIncidents(incidents)

    return data


async def get_bot_id_async() -> str:
    """
    Gets the app bot ID

    Returns:
        The app bot ID
    """
    response = await ASYNC_CLIENT.auth_test()
    return response.get('bot_id')


async def listen(client: SocketModeClient, req: SocketModeRequest):
    demisto.info("Handling request")
    if req.envelope_id:
        response = SocketModeResponse(envelope_id=req.envelope_id)
        await client.send_socket_mode_response(response)
    data_type: str = req.type
    payload: dict = req.payload
    if data_type == 'error':
        error = payload.get('error', {})
        error_code = error.get('code')
        error_msg = error.get('msg')
        await handle_listen_error(
            f'Slack API has thrown an error. Code: {error_code}, Message: {error_msg}.')
        return

    try:
        data: dict = req.payload
        event: dict = data.get('event', {})
        subtype = data.get('subtype', '')
        text = event.get('text', '')
        user_id = event.get('user', '')
        channel = event.get('channel', '')
        message_bot_id = data.get('bot_id', '')
        thread = event.get('thread_ts', None)
        message = data.get('message', {})
        entitlement_reply = None
        # Check if slash command received. If so, ignore for now.
        if data.get('command', None):
            demisto.debug("Slash command event received. Ignoring.")
            return

        actions = data.get('actions', [])
        integration_context = get_integration_context(SYNC_CONTEXT)
        if subtype == 'bot_message' or message_bot_id or message.get('subtype') == 'bot_message' \
                or \
                event.get('bot_id', None):

            if integration_context.get('bot_user_id'):
                bot_id = integration_context['bot_user_id']
                if bot_id == 'null' or bot_id is None:
                    # In some cases the bot_id can be stored as a string 'null', this handles this edge case.
                    bot_id = await get_bot_id_async()
                    set_to_integration_context_with_retries({'bot_user_id': bot_id}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
            else:
                bot_id = await get_bot_id_async()
                set_to_integration_context_with_retries({'bot_user_id': bot_id}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
            if event.get('subtype') == 'bot_message':
                demisto.debug("Received bot_message event type. Ignoring.")
                return
            if event.get('bot_id', None) in bot_id:
                demisto.debug("Received bot message from the current bot. Ignoring.")
                return
        if event.get('subtype') == 'message_changed':
            demisto.debug("Received message_changed event type. Ignoring.")
            return
        if event.get('subtype') == 'file_share':
            if event.get('client_msg_id'):
                demisto.debug('Received file_share event type. Processing.')
            else:
                demisto.debug('Got a file that is a mirror from XSOAR. Ignoring')
                return
            

        if len(actions) > 0:
            channel = data.get('channel', {}).get('id', '')
            user_id = data.get('user', {}).get('id', '')
            entitlement_json = actions[0].get('value')
            entitlement_string = json.loads(entitlement_json)
            entitlement_reply = json.loads(entitlement_json).get("reply", "Thank you for your reply.")
            action_text = actions[0].get('text').get('text')
            user = await ASYNC_CLIENT.users_info(user=user_id)
            answer_question(action_text, entitlement_string, user.get('profile', {}).get('email'))

        else:
            if user_id != '':
                # User ID is returned as an empty string
                user = await get_user_by_id_async(ASYNC_CLIENT, user_id)  # type: ignore
                entitlement_reply = await check_and_handle_entitlement(text, user, thread)  # type: ignore

        if entitlement_reply:
            await send_slack_request_async(
                client=ASYNC_CLIENT,
                method='chat.postMessage',
                body={
                    'channel': channel,
                    'thread_ts': thread,
                    'text': entitlement_reply
                }
            )

        elif channel and channel[0] == 'D' and ENABLE_DM:
            # DM
            await handle_dm(user, text, ASYNC_CLIENT)  # type: ignore
        else:
            channel_id = channel

            if not integration_context or 'mirrors' not in integration_context:
                return

            mirrors = json.loads(integration_context['mirrors'])
            mirror_filter = list(filter(lambda m: m['channel_id'] == channel_id, mirrors))
            if not mirror_filter:
                demisto.info("No mirror filter")
                return

            for mirror in mirror_filter:
                if mirror['mirror_direction'] == 'FromDemisto' or mirror['mirror_type'] == 'none':
                    return

                if not mirror['mirrored']:
                    demisto.info("Not mirrored yet")
                    # In case the investigation is not mirrored yet
                    mirror = mirrors.pop(mirrors.index(mirror))
                    if mirror['mirror_to'] and mirror['mirror_direction'] and mirror['mirror_type']:
                        investigation_id = mirror['investigation_id']
                        mirror_type = mirror['mirror_type']
                        auto_close = mirror['auto_close']
                        direction = mirror['mirror_direction']
                        if isinstance(auto_close, str):
                            auto_close = bool(strtobool(auto_close))
                        demisto.info(f'Mirroring: {investigation_id}')
                        demisto.mirrorInvestigation(investigation_id,
                                                    f'{mirror_type}:{direction}', auto_close)
                        mirror['mirrored'] = True
                        mirrors.append(mirror)
                        set_to_integration_context_with_retries({'mirrors': mirrors},
                                                                OBJECTS_TO_KEYS, SYNC_CONTEXT)

                investigation_id = mirror['investigation_id']
                # Post to the warroom
                if event.get('subtype') == 'file_share':
                    for file_obj in event.get('files', []):
                        data = await get_file(ASYNC_CLIENT, file_obj.get('url_private'))
                        name = file_obj.get('name')
                        file_ = fileResult(name, data, investigation_id=investigation_id)
                        demisto.debug('after file result')
                        demisto.debug(f'{file_=}')
                        await handle_file(
                            investigation_id,
                            file_,
                            user  # type: ignore
                        )

                else:
                    await handle_text(ASYNC_CLIENT, investigation_id, text, user)  # type: ignore
        # Reset module health
        demisto.updateModuleHealth("")
        demisto.info("SlackV3 - Event handled successfully.")

    except Exception as e:
        await handle_listen_error(f'Error occurred while listening to Slack: {e}')


async def get_user_by_id_async(client: AsyncWebClient, user_id: str) -> dict:
    """
    Get the details of a slack user by id asynchronously.
    Args:
        client: The slack web client to use.
        user_id: The id of the user.

    Returns:
        The slack user.
    """
    user: dict = {}
    users: list = []
    integration_context = get_integration_context(SYNC_CONTEXT)
    if integration_context.get('users'):
        users = json.loads(integration_context['users'])
        user_filter = list(filter(lambda u: u['id'] == user_id, users))
        if user_filter:
            user = user_filter[0]
    if not user:
        body = {
            'user': user_id
        }
        user = (
            await send_slack_request_async(client, 'users.info', http_verb='GET', body=body)).get(
            'user', {})
        users.append(user)
        set_to_integration_context_with_retries({'users': users}, OBJECTS_TO_KEYS, SYNC_CONTEXT)

    return user


async def handle_file(
    investigation_id: str,
    file_result: dict,
    user: dict
):
    demisto.info(f'SlackV3 - adding file entry to incident {investigation_id}')
    demisto.addEntry(
        id=investigation_id,
        entry=json.dumps(file_result),
        username=user.get('name', ''),
        email=user.get('profile', {}).get('email', ''),
        footer=MESSAGE_FOOTER,
        entryType=EntryType.FILE
    )


async def handle_text(client: AsyncWebClient, investigation_id: str, text: str, user: dict):
    """
    Handles text received in the Slack workspace (not DM)

    Args:
        client: The Slack client
        investigation_id: The mirrored investigation ID
        text: The received text
        user: The sender
    """
    if text:
        demisto.info(f'SlackV3 - adding entry to incident {investigation_id}')
        demisto.addEntry(
            id=investigation_id,
            entry=await clean_message(text, client),
            username=user.get('name', ''),
            email=user.get('profile', {}).get('email', ''),
            footer=MESSAGE_FOOTER
        )
        demisto.info("SlackV3 - Text handled successfully.")
    else:
        demisto.info('Entry does not added to incident, no text supplied')


async def check_and_handle_entitlement(text: str, user: dict, thread_id: str) -> str:
    """
    Handles an entitlement message (a reply to a question)
    Args:
        text: The message text
        user: The user who sent the reply
        thread_id: The thread ID

    Returns:
        If the message contains entitlement, return a reply.
    """

    entitlement_match = re.search(ENTITLEMENT_REGEX, text)
    if entitlement_match:
        demisto.info('Slack - handling entitlement in message.')
        content, guid, incident_id, task_id = extract_entitlement(entitlement_match.group(), text)
        demisto.handleEntitlementForUser(incident_id, guid, user.get('profile', {}).get('email'), content, task_id)

        return 'Thank you for your response.'
    else:
        integration_context = get_integration_context(SYNC_CONTEXT)
        questions = integration_context.get('questions', [])
        if questions and thread_id:
            questions = json.loads(questions)
            question_filter = list(filter(lambda q: q.get('thread') == thread_id, questions))
            if question_filter:
                question = question_filter[0]
                demisto.info('Slack - handling entitlement in thread.')
                entitlement = question.get('entitlement')
                reply = question.get('reply', 'Thank you for your response.')
                content, guid, incident_id, task_id = extract_entitlement(entitlement, text)
                demisto.handleEntitlementForUser(incident_id, guid, user.get('profile', {}).get('email'), content,
                                                 task_id)
                question['remove'] = True
                set_to_integration_context_with_retries({'questions': questions}, OBJECTS_TO_KEYS, SYNC_CONTEXT)

                return reply

    return ''


''' SEND '''


def get_conversation_by_name(conversation_name: str) -> dict:
    """
    Get a slack conversation by its name

    Args:
        conversation_name: The conversation name

    Returns:
        The slack conversation
    """
    integration_context = get_integration_context(SYNC_CONTEXT)

    conversation_to_search = conversation_name.lower()
    # Find conversation in the cache
    conversations = integration_context.get('conversations')
    if conversations:
        conversations = json.loads(conversations)
        conversation_filter = list(
            filter(
                lambda c: conversation_to_search == c.get('name', '').lower(),
                conversations
            )
        )
        if conversation_filter:
            return conversation_filter[0]

    demisto.debug(f'could not find slack channel "{conversation_to_search}" in integration context, searching via API')
    # If not found in cache, search for it
    body = {
        'types': 'private_channel,public_channel',
        'limit': PAGINATED_COUNT
    }
    response = send_slack_request_sync(CLIENT, 'conversations.list', http_verb='GET', body=body)

    conversation: dict = {}
    while True:
        conversations = response['channels'] if response and response.get('channels') else []
        cursor = response.get('response_metadata', {}).get('next_cursor')
        conversation_filter = list(filter(lambda c: c.get('name') == conversation_name, conversations))
        if conversation_filter:
            break
        if not cursor:
            demisto.info("Reached the end of looking for a channel")
            break

        body = body.copy()  # strictly for unit-test purposes (test_get_conversation_by_name_paging)
        body.update({'cursor': cursor})
        response = send_slack_request_sync(CLIENT, 'conversations.list', http_verb='GET', body=body)
    if conversation_filter:
        conversation = conversation_filter[0]

    # Save conversations to cache
    if conversation:
        conversations = integration_context.get('conversations')
        if conversations:
            conversations = json.loads(conversations)
            conversations.append(conversation)
        else:
            conversations = [conversation]
        set_to_integration_context_with_retries({'conversations': conversations}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
    return conversation


def slack_send():
    """
    Sends a message to slack
    """

    args = demisto.args()
    message = args.get('message', '')
    to = args.get('to')
    original_channel = args.get('channel')
    group = args.get('group')
    message_type = args.get('messageType', '')  # From server
    original_message = args.get('originalMessage', '')  # From server
    entry = args.get('entry')
    ignore_add_url = args.get('ignoreAddURL', False) or args.get('IgnoreAddURL', False)
    thread_id = args.get('threadID', '')
    severity = args.get('severity')  # From server
    blocks = args.get('blocks')
    entry_object = args.get('entryObject')  # From server, available from demisto v6.1 and above
    entitlement = ''

    if message_type and (message_type not in PERMITTED_NOTIFICATION_TYPES):
        if message_type != MIRROR_TYPE:
            demisto.info(f"Message type is not in permitted options. Received: {message_type}")
            return

    if message_type == MIRROR_TYPE and original_message.find(MESSAGE_FOOTER) != -1:
        # return so there will not be a loop of messages
        return

    if message_type == MIRROR_TYPE:
        tags = argToList(demisto.params().get('filtered_tags', []))
        entry_tags = entry_object.get('tags', [])

        if tags and not entry_tags:
            return

        # return if the entry tags is not containing any of the filtered_tags
        if tags and not any(elem in entry_tags for elem in tags):
            return

    if (to and group) or (to and original_channel) or (to and original_channel and group):
        return_error('Only one destination can be provided.')

    if severity:
        try:
            severity = int(severity)
        except Exception:
            severity = None

    channel = original_channel
    if original_channel == INCIDENT_NOTIFICATION_CHANNEL or (not original_channel and message_type == INCIDENT_OPENED):
        original_channel = INCIDENT_NOTIFICATION_CHANNEL
        channel = DEDICATED_CHANNEL
        demisto.debug(f'trying to send message to channel {original_channel}, changing slack channel to {channel}')

    if (channel == DEDICATED_CHANNEL and original_channel == INCIDENT_NOTIFICATION_CHANNEL
            and ((severity is not None and severity < SEVERITY_THRESHOLD)
                 or not (len(PERMITTED_NOTIFICATION_TYPES) > 0))):
        channel = None

    if not (to or group or channel):
        return_error('Either a user, group or channel must be provided.')

    reply = ''
    expiry = ''
    default_response = ''
    if blocks:
        entitlement_match = re.search(ENTITLEMENT_REGEX, blocks)
        if entitlement_match:
            try:
                parsed_message = json.loads(blocks)
                entitlement = parsed_message.get('entitlement')
                blocks = parsed_message.get('blocks')
                reply = parsed_message.get('reply')
                expiry = parsed_message.get('expiry')
                default_response = parsed_message.get('default_response')
            except Exception:
                demisto.info('Slack - could not parse JSON from entitlement blocks.')
    elif message:
        entitlement_match = re.search(ENTITLEMENT_REGEX, message)
        if entitlement_match:
            try:
                parsed_message = json.loads(message)
                entitlement = parsed_message.get('entitlement')
                message = parsed_message.get('message')
                reply = parsed_message.get('reply')
                expiry = parsed_message.get('expiry')
                default_response = parsed_message.get('default_response')
            except Exception:
                demisto.info('Slack - could not parse JSON from entitlement message.')
    file_dict = MirrorInvestigation.get_file_from_incoming_entry(args)
    response = slack_send_request(
        to, channel, group, entry, ignore_add_url, thread_id,
        message=message, blocks=blocks, file_dict=file_dict
    )

    if response:
        thread = response.get('ts')
        if entitlement:
            save_entitlement(entitlement, thread, reply, expiry, default_response)

        demisto.results({
            'Type': entryTypes['note'],
            'HumanReadable': f'Message sent to Slack successfully.\nThread ID is: {thread}',
            'Contents': response.data,
            'ContentsFormat': formats['json'],
            'EntryContext': {
                'Slack.Thread(val.ID===obj.ID)': {
                    'ID': thread
                },
            }
        })
    else:
        demisto.results('Could not send the message to Slack.')


def save_entitlement(entitlement, thread, reply, expiry, default_response):
    """
    Saves an entitlement with its thread

    Args:
        entitlement: The entitlement
        thread: The thread
        reply: The reply to send to the user.
        expiry: The question expiration date.
        default_response: The response to send if the question times out.
    """
    integration_context = get_integration_context(SYNC_CONTEXT)
    questions = integration_context.get('questions', [])
    if questions:
        questions = json.loads(integration_context['questions'])
    questions.append({
        'thread': thread,
        'entitlement': entitlement,
        'reply': reply,
        'expiry': expiry,
        'sent': datetime.strftime(get_current_utc_time(), DATE_FORMAT),
        'default_response': default_response
    })

    set_to_integration_context_with_retries({'questions': questions}, OBJECTS_TO_KEYS, SYNC_CONTEXT)


def slack_send_file():
    """
    Sends a file to slack
    """
    to = demisto.args().get('to')
    channel = demisto.args().get('channel')
    group = demisto.args().get('group')
    entry_id = demisto.args().get('file')
    thread_id = demisto.args().get('threadID')
    comment = demisto.args().get('comment', '')

    if not (to or channel or group):
        mirror = find_mirror_by_investigation()
        if mirror:
            channel = mirror.get('channel_name')

    if not (to or channel or group):
        return_error('Either a user, group or channel must be provided.')

    file_path = demisto.getFilePath(entry_id)

    file_dict = {
        'path': file_path['path'],
        'name': file_path['name'],
        'comment': comment
    }

    response = slack_send_request(to, channel, group, thread_id=thread_id, file_dict=file_dict)
    if response:
        demisto.results('File sent to Slack successfully.')
    else:
        demisto.results('Could not send the file to Slack.')


def handle_tags_in_message_sync(message: str) -> str:
    """
    Handles user tags in a slack send message

    Args:
        message: The slack message

    Returns:
        The tagged slack message
    """
    matches = re.findall(USER_TAG_EXPRESSION, message)
    message = re.sub(USER_TAG_EXPRESSION, r'\1', message)
    for match in matches:
        slack_user = get_user_by_name(match)
        if slack_user:
            message = message.replace(match, f"<@{slack_user.get('id')}>")

    resolved_message = re.sub(URL_EXPRESSION, r'\1', message)

    return resolved_message


def send_message(destinations: list, entry: str, ignore_add_url: bool, integration_context: dict, message: str,
                 thread_id: str, blocks: str):
    """
    Sends a message to Slack.
    Args:
        destinations: The destinations to send to.
        entry: A WarRoom entry to send.
        ignore_add_url: Do not add a XSOAR URL to the message.
        integration_context: Current integration context.
        message: The message to send.
        thread_id: The Slack thread ID to send the message to.
        blocks: Message blocks to send

    Returns:
        The Slack send response.
    """
    if not message:
        if blocks:
            message = 'New message from SOC Bot'
            # This is shown in the notification bubble from Slack
        else:
            message = '\n'

    if message and not blocks:
        if ignore_add_url and isinstance(ignore_add_url, str):
            ignore_add_url = bool(strtobool(ignore_add_url))
        if not ignore_add_url:
            investigation = demisto.investigation()
            server_links = demisto.demistoUrls()
            if investigation:
                if investigation.get('type') != PLAYGROUND_INVESTIGATION_TYPE:
                    link = server_links.get('warRoom')
                    if link:
                        if entry:
                            link += '/' + entry
                        message += f'\nView it on: {link}'
                else:
                    link = server_links.get('server', '')
                    if link:
                        message += f'\nView it on: {link}#/home'
    try:
        response = send_message_to_destinations(destinations, message, thread_id, blocks)
    except SlackApiError as e:
        if str(e).find('not_in_channel') == -1 and str(e).find('channel_not_found') == -1:
            raise
        bot_id = integration_context.get('bot_id')
        if not bot_id:
            bot_id = get_bot_id()
        for dest in destinations:
            invite_users_to_conversation(dest, [bot_id])
        response = send_message_to_destinations(destinations, message, thread_id, blocks)
    return response


def send_message_to_destinations(destinations: list, message: str, thread_id: str, blocks: str = '') \
        -> Optional[SlackResponse]:
    """
    Sends a message to provided destinations Slack.

    Args:
        destinations: Destinations to send to.
        message: The message to send.
        thread_id: Slack thread ID to send to.
        blocks: Message blocks to send

    Returns:
        The Slack send response.
    """
    response: Optional[SlackResponse] = None
    body: dict = {}

    if message:
        clean_message = handle_tags_in_message_sync(message)
        body['text'] = clean_message
    if blocks:
        block_list = json.loads(blocks, strict=False)
        body['blocks'] = block_list
    if thread_id:
        body['thread_ts'] = thread_id

    for destination in destinations:
        body['channel'] = destination
        response = send_slack_request_sync(CLIENT, 'chat.postMessage', body=body)

    return response


def send_file(destinations: list, file_dict: dict, integration_context: dict, thread_id: str) -> \
        Optional[SlackResponse]:
    """
    Sends a file to Slack.

    Args:
        destinations: Destinations to send the file to.
        file_dict: The file to send.
        integration_context: The current integration context.
        thread_id: A Slack thread to send to.

    Returns:
        The Slack send response.
    """
    try:
        response = send_file_to_destinations(destinations, file_dict, thread_id)
    except SlackApiError as e:
        if str(e).find('not_in_channel') == -1 and str(e).find('channel_not_found') == -1:
            raise
        bot_id = integration_context.get('bot_id')
        if not bot_id:
            bot_id = get_bot_id()
            integration_context['bot_id'] = bot_id
        for dest in destinations:
            invite_users_to_conversation(dest, [bot_id])
        response = send_file_to_destinations(destinations, file_dict, thread_id)

    return response


def send_file_to_destinations(destinations: list, file_dict: dict, thread_id: str) -> Optional[SlackResponse]:
    """
    Sends a file to provided destinations in Slack.

    Args:
        destinations: The destinations to send to.
        file_dict: The file to send.
        thread_id: A thread ID to send to.

    Returns:
        The Slack send response.
    """
    response: Optional[SlackResponse] = None
    body = {
        'filename': file_dict['name']
    }

    if comment := file_dict.get('comment'):
        body['initial_comment'] = comment

    for destination in destinations:
        body['channels'] = destination
        if thread_id:
            body['thread_ts'] = thread_id

        response = send_slack_request_sync(CLIENT, 'files.upload', file_=file_dict['path'], body=body)

    return response


def slack_send_request(to: str, channel: str, group: str, entry: str = '', ignore_add_url: bool = False,
                       thread_id: str = '', message: str = '', blocks: str = '', file_dict: dict = None) \
        -> Optional[SlackResponse]:
    """
    Requests to send a message or a file to Slack.

    Args:
        to: A Slack user to send to.
        channel: A Slack channel to send to.
        group: A Slack private channel to send to.
        entry: WarRoom entry to send.
        ignore_add_url: Do not add a Demisto URL to the message.
        thread_id: The Slack thread ID to send to.
        message: A message to send.
        blocks: Blocks to send with a slack message
        file_dict: A file to send.

    Returns:
        The Slack send response.
    """

    integration_context = get_integration_context(SYNC_CONTEXT)
    mirrors: list = []
    if integration_context:
        if 'mirrors' in integration_context:
            mirrors = json.loads(integration_context['mirrors'])

    destinations = []

    if to:
        if isinstance(to, list):
            to = to[0]
        user = get_user_by_name(to)
        if not user:
            demisto.error(f'Could not find the Slack user {to}')
        else:
            body = {
                'users': user.get('id')
            }
            im = send_slack_request_sync(CLIENT, 'conversations.open', body=body)
            destinations.append(im.get('channel', {}).get('id'))
    if channel or group:
        if not destinations:
            destination_name = channel or group
            mirrored_channel_filter = list(filter(lambda m: f'incident-{m["investigation_id"]}' == destination_name,
                                                  mirrors))
            if mirrored_channel_filter:
                channel_mirror = mirrored_channel_filter[0]
                conversation_id = channel_mirror['channel_id']
            else:
                conversation = get_conversation_by_name(destination_name)
                if not conversation:
                    return_error(f'Could not find the Slack conversation {destination_name}')
                conversation_id = conversation.get('id')

            if conversation_id:
                destinations.append(conversation_id)

    if not destinations:
        return_error('Could not find any destination to send to.')

    if file_dict:
        response = send_file(destinations, file_dict, integration_context, thread_id)
        return response

    response = send_message(destinations, entry, ignore_add_url, integration_context, message,
                            thread_id, blocks)

    return response


def set_channel_topic():
    """
    Sets a topic for a slack channel
    """

    channel = demisto.args().get('channel')
    topic = demisto.args().get('topic')

    channel_id = ''

    if not channel:
        mirror = find_mirror_by_investigation()
        if mirror:
            channel_id = mirror.get('channel_id', '')
            # We need to update the topic in the mirror
            integration_context = get_integration_context(SYNC_CONTEXT)
            mirrors = json.loads(integration_context['mirrors'])
            mirror = mirrors.pop(mirrors.index(mirror))
            mirror['channel_topic'] = topic
            mirrors.append(mirror)
            set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
    else:
        channel = get_conversation_by_name(channel)
        channel_id = channel.get('id')

    if not channel_id:
        return_error('Channel was not found - Either the Slack app is not a member of the channel, '
                     'or the slack app does not have permission to find the channel.')

    body = {
        'channel': channel_id,
        'topic': topic
    }
    send_slack_request_sync(CLIENT, 'conversations.setTopic', body=body)

    demisto.results('Topic successfully set.')


def rename_channel():
    """
    Renames a slack channel
    """

    channel = demisto.args().get('channel')
    new_name = demisto.args().get('name')

    channel_id = ''

    if not channel:
        mirror = find_mirror_by_investigation()
        if mirror:
            channel_id = mirror.get('channel_id', '')
            # We need to update the name in the mirror
            integration_context = get_integration_context(SYNC_CONTEXT)
            mirrors = json.loads(integration_context['mirrors'])
            mirror = mirrors.pop(mirrors.index(mirror))
            mirror['channel_name'] = new_name
            mirrors.append(mirror)
            set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
    else:
        channel = get_conversation_by_name(channel)
        channel_id = channel.get('id')

    if not channel_id:
        return_error('Channel was not found - Either the Slack app is not a member of the channel, '
                     'or the slack app does not have permission to find the channel.')
    body = {
        'channel': channel_id,
        'name': new_name
    }
    send_slack_request_sync(CLIENT, 'conversations.rename', body=body)

    demisto.results('Channel renamed successfully.')


def close_channel():
    """
    Archives a slack channel by name or its incident ID if mirrored.
    """
    channel = demisto.args().get('channel')
    channel_id = ''

    if not channel:
        mirror = find_mirror_by_investigation()
        if mirror:
            channel_id = mirror.get('channel_id', '')
            # We need to update the topic in the mirror
            integration_context = get_integration_context(SYNC_CONTEXT)
            mirrors = json.loads(integration_context['mirrors'])
            channel_id = mirror['channel_id']
            # Check for mirrors on the archived channel
            channel_mirrors = list(filter(lambda m: channel_id == m['channel_id'], mirrors))
            for mirror in channel_mirrors:
                mirror['remove'] = True
                demisto.mirrorInvestigation(mirror['investigation_id'], f'none:{mirror["mirror_direction"]}',
                                            mirror['auto_close'])

            set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
    else:
        channel = get_conversation_by_name(channel)
        channel_id = channel.get('id')

    if not channel_id:
        return_error('Channel was not found - Either the Slack app is not a member of the channel, '
                     'or the slack app does not have permission to find the channel.')
    body = {
        'channel': channel_id
    }
    send_slack_request_sync(CLIENT, 'conversations.archive', body=body)

    demisto.results('Channel successfully archived.')


def create_channel():
    """
    Creates a channel in Slack using the provided arguments.
    """
    channel_type = demisto.args().get('type', 'private')
    channel_name = demisto.args()['name']
    users = argToList(demisto.args().get('users', []))
    topic = demisto.args().get('topic')

    body = {
        'name': channel_name
    }

    if channel_type == 'private':
        body['is_private'] = True

    conversation = send_slack_request_sync(CLIENT, 'conversations.create', body=body).get(
        'channel', {})

    if users:
        slack_users = search_slack_users(users)
        invite_users_to_conversation(conversation.get('id'),
                                     list(map(lambda u: u.get('id'), slack_users)))
    if topic:
        body = {
            'channel': conversation.get('id'),
            'topic': topic
        }
        send_slack_request_sync(CLIENT, 'conversations.setTopic', body=body)
    created_channel_name = conversation.get('name')
    demisto.results(f'Successfully created the channel {created_channel_name}')


def invite_to_channel():
    channel = demisto.args().get('channel')
    users = argToList(demisto.args().get('users', []))

    channel_id = ''

    if not channel:
        mirror = find_mirror_by_investigation()
        if mirror:
            channel_id = mirror['channel_id']
    else:
        channel = get_conversation_by_name(channel)
        channel_id = channel.get('id')

    if not channel_id:
        return_error('Channel was not found - Either the Slack app is not a member of the channel, '
                     'or the slack app does not have permission to find the channel.')
    slack_users = search_slack_users(users)
    if slack_users:
        invite_users_to_conversation(channel_id, list(map(lambda u: u.get('id'), slack_users)))
    else:
        return_error('No users found')

    demisto.results('Successfully invited users to the channel.')


def kick_from_channel():
    channel = demisto.args().get('channel')
    users = argToList(demisto.args().get('users', []))

    channel_id = ''

    if not channel:
        mirror = find_mirror_by_investigation()
        if mirror:
            channel_id = mirror['channel_id']
    else:
        channel = get_conversation_by_name(channel)
        channel_id = channel.get('id')

    if not channel_id:
        return_error('Channel was not found - Either the Slack app is not a member of the channel, '
                     'or the slack app does not have permission to find the channel.')
    slack_users = search_slack_users(users)
    if slack_users:
        kick_users_from_conversation(channel_id, list(map(lambda u: u.get('id'), slack_users)))
    else:
        return_error('No users were found')

    demisto.results('Successfully kicked users from the channel.')


def get_user():
    user = demisto.args()['user']

    slack_user = get_user_by_name(user)
    if not slack_user:
        return_error('User not found')

    profile = slack_user.get('profile', {})
    result_user = {
        'ID': slack_user.get('id'),
        'Username': slack_user.get('name'),
        'Name': profile.get('real_name_normalized') or profile.get('real_name'),
        'DisplayName': profile.get('display_name'),
        'Email': profile.get('email')
    }

    hr = tableToMarkdown('Details for Slack user: ' + user, result_user,
                         headers=['ID', 'Username', 'Name', 'DisplayName', 'Email'], headerTransform=pascalToSpace,
                         removeNull=True)
    context = {
        'Slack.User(val.ID === obj.ID)': createContext(result_user, removeNull=True)
    }

    return_outputs(hr, context, slack_user)


def slack_edit_message():
    args = demisto.args()
    channel = args.get('channel')
    thread_id = demisto.args().get('threadID')
    message = args.get('message')
    blocks = args.get('blocks')
    ignore_add_url = args.get('ignore_add_url')
    entry = args.get('entry')

    channel_id = ''

    if not channel:
        mirror = find_mirror_by_investigation()
        if mirror:
            channel_id = mirror['channel_id']
    else:
        channel = get_conversation_by_name(channel)
        channel_id = channel.get('id')

    if not channel_id:
        return_error('Channel was not found - Either the Slack app is not a member of the channel, '
                     'or the slack app does not have permission to find the channel.')
    if not thread_id:
        return_error('The timestamp of the message to edit is required.')

    if message and not blocks:
        if ignore_add_url and isinstance(ignore_add_url, str):
            ignore_add_url = bool(strtobool(ignore_add_url))
        if not ignore_add_url:
            investigation = demisto.investigation()
            server_links = demisto.demistoUrls()
            if investigation:
                if investigation.get('type') != PLAYGROUND_INVESTIGATION_TYPE:
                    link = server_links.get('warRoom')
                    if link:
                        if entry:
                            link += '/' + entry
                        message += f'\nView it on: {link}'
                else:
                    link = server_links.get('server', '')
                    if link:
                        message += f'\nView it on: {link}#/home'

    body = {
        'channel': channel_id,
        'ts': thread_id
    }
    if message:
        clean_message = handle_tags_in_message_sync(message)
        body['text'] = clean_message
    if blocks:
        block_list = json.loads(blocks, strict=False)
        body['blocks'] = block_list
    try:
        response = send_slack_request_sync(CLIENT, 'chat.update', body=body)

        hr = "The message was successfully edited."
        result_edit = {
            'ID': response.get('ts', None),
            'Channel': response.get('channel', None),
            'Text': response.get('text', None)
        }
        context = {
            'Slack.Thread(val.ID === obj.ID)': result_edit
        }
        return_results(CommandResults(
            readable_output=hr,
            outputs=context,
            raw_response=json.dumps(response.data)))

    except SlackApiError as slack_error:
        return_error(f"{slack_error}")


def pin_message():
    channel = demisto.args().get('channel')
    thread_id = demisto.args().get('threadID')

    channel_id = ''

    if not channel:
        mirror = find_mirror_by_investigation()
        if mirror:
            channel_id = mirror['channel_id']
    else:
        channel = get_conversation_by_name(channel)
        channel_id = channel.get('id')

    if not channel_id:
        return_error('Channel was not found - Either the Slack app is not a member of the channel, '
                     'or the slack app does not have permission to find the channel.')
    body = {
        'channel': channel_id,
        'timestamp': thread_id
    }
    try:
        send_slack_request_sync(CLIENT, 'pins.add', body=body)
        return_results('The message was successfully pinned.')

    except SlackApiError as slack_error:
        return_error(f"{slack_error}")


def long_running_main():
    """
    Starts the long running thread.
    """
    try:
        asyncio.run(start_listening(), debug=True)
    except Exception as e:
        demisto.error(f"The Loop has failed to run {str(e)}")
    finally:
        loop = asyncio.get_running_loop()
        try:
            loop.stop()
            loop.close()
        except Exception as e_:
            demisto.error(f'Failed to gracefully close the loop - {e_}')


def init_globals(command_name: str = ''):
    """
    Initializes global variables according to the integration parameters
    """
    global BOT_TOKEN, PROXY_URL, PROXIES, DEDICATED_CHANNEL, CLIENT
    global SEVERITY_THRESHOLD, ALLOW_INCIDENTS, INCIDENT_TYPE, VERIFY_CERT, ENABLE_DM
    global BOT_NAME, BOT_ICON_URL, MAX_LIMIT_TIME, PAGINATED_COUNT, SSL_CONTEXT, APP_TOKEN, ASYNC_CLIENT
    global PERMITTED_NOTIFICATION_TYPES

    VERIFY_CERT = not demisto.params().get('unsecure', False)
    if not VERIFY_CERT:
        SSL_CONTEXT = ssl.create_default_context()
        SSL_CONTEXT.check_hostname = False
        SSL_CONTEXT.verify_mode = ssl.CERT_NONE
    else:
        # Use default SSL context
        SSL_CONTEXT = None

    if command_name == 'long-running-execution':
        loop = asyncio.get_event_loop()
        if not loop._default_executor:  # type: ignore[attr-defined]
            demisto.info(f'setting _default_executor on loop: {loop} id: {id(loop)}')
            loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=4))

    BOT_TOKEN = demisto.params().get('bot_token', {}).get('password', '')
    APP_TOKEN = demisto.params().get('app_token', {}).get('password', '')
    PROXIES = handle_proxy()
    PROXY_URL = PROXIES.get('http')  # aiohttp only supports http proxy
    DEDICATED_CHANNEL = demisto.params().get('incidentNotificationChannel', None)
    ASYNC_CLIENT = AsyncWebClient(token=BOT_TOKEN, ssl=SSL_CONTEXT, proxy=PROXY_URL)
    CLIENT = slack_sdk.WebClient(token=BOT_TOKEN, proxy=PROXY_URL, ssl=SSL_CONTEXT)
    SEVERITY_THRESHOLD = SEVERITY_DICT.get(demisto.params().get('min_severity', 'Low'), 1)
    ALLOW_INCIDENTS = demisto.params().get('allow_incidents', False)
    INCIDENT_TYPE = demisto.params().get('incidentType')
    BOT_NAME = demisto.params().get('bot_name')  # Bot default name defined by the slack plugin (3-rd party)
    BOT_ICON_URL = demisto.params().get('bot_icon')  # Bot default icon url defined by the slack plugin (3-rd party)
    MAX_LIMIT_TIME = int(demisto.params().get('max_limit_time', '60'))
    PAGINATED_COUNT = int(demisto.params().get('paginated_count', '200'))
    ENABLE_DM = demisto.params().get('enable_dm', True)
    PERMITTED_NOTIFICATION_TYPES = demisto.params().get('permitted_notifications', [])


def print_thread_dump():
    demisto.info(f'current thread: {threading.current_thread().name}')
    for threadId, stack in sys._current_frames().items():
        stack_str = '\n'.join(traceback.format_stack(stack))
        demisto.info(f'{threadId} stack: {stack_str}')


def loop_info(loop: asyncio.AbstractEventLoop):
    if not loop:
        return "loop is None"
    info = f'loop: {loop}. id: {id(loop)}.'
    info += f'executor: {loop._default_executor} id: {id(loop._default_executor)}'  # type: ignore[attr-defined]
    if loop._default_executor:  # type: ignore[attr-defined]
        info += f' executor threads size: {len(loop._default_executor._threads)}'  # type: ignore[attr-defined]
        info += f' max: {loop._default_executor._max_workers} {loop._default_executor._threads}'  # type: ignore[attr-defined]
    return info


def slack_get_integration_context():
    integration_context = get_integration_context()
    return_results(fileResult('slack_integration_context', json.dumps(integration_context), EntryType.ENTRY_INFO_FILE))


def main() -> None:
    """
    Main
    """
    global CLIENT
    if is_debug_mode():
        os.environ['PYTHONASYNCIODEBUG'] = "1"

    commands = {
        'test-module': test_module,
        'long-running-execution': long_running_main,
        'mirror-investigation': mirror_investigation,
        'send-notification': slack_send,
        'slack-send-file': slack_send_file,
        'slack-set-channel-topic': set_channel_topic,
        'close-channel': close_channel,
        'slack-create-channel': create_channel,
        'slack-invite-to-channel': invite_to_channel,
        'slack-kick-from-channel': kick_from_channel,
        'slack-rename-channel': rename_channel,
        'slack-get-user-details': get_user,
        'slack-get-integration-context': slack_get_integration_context,
        'slack-edit-message': slack_edit_message,
        'slack-pin-message': pin_message
    }

    command_name: str = demisto.command()

    try:
        demisto.info(f'{command_name} started.')
        command_func = commands[command_name]
        init_globals(command_name)
        support_multithreading()
        command_func()
    except Exception as e:
        LOG(e)
        return_error(str(e))
    finally:
        demisto.info(
            f'{command_name} completed.')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
