import asyncio
from loguru import logger
import uuid
from asyncio import Task
from typing import *
import time
import json
import base64

from urllib.parse import urlparse

from nostr.event import EventKind, Event
from nostr.filter import Filters, Filter
from nostr.key import PrivateKey, PublicKey
from nostr.message_pool import EventMessage
from nostr.message_type import ClientMessageType
from nostr.relay_manager import RelayManager
from cryptography.hazmat.primitives import hashes

from nostrest.event_utils import encrypt_to_event, decrypt_event, NOSTREST_EPHEMERAL_EVENT_KIND
from nostrest.jsonrpcish import JsonRpcRequest, JsonRpcResponse, JsonRpcNostrestParams
from nostrest.nostreststate import NostrestState
from nostrest.nostrrequest import NostrRequest
from typing import Callable

from nostrest.restresponse import RestResponse

TOKEN_APP_URL_SCHEMA = 'cashu:'

def _generate_token_id(token: str):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(token, 'utf-8'))
    return base64.b64encode(digest.finalize()[0:8]).decode('utf-8').replace('=', '')


def _extract_recipient_public_key_hex_from_event(event: Event):
    if len(event.tags) == 0:
        return None
    for tag in event.tags:
        if len(tag) == 2 and tag[0] == 'p':
            return tag[1]
    return None


class Nostrest:
    relay_manager: RelayManager = RelayManager()
    pending_requests: dict[str, NostrRequest] = {}
    pending_keys: dict[str, PrivateKey] = {}
    static_private_key: PrivateKey
    poller: Task
    is_running: bool = False
    state_file: str
    state: NostrestState
    lock: asyncio.Lock = asyncio.Lock()

    token_received_callback: Callable[[str, str], bool] = None

    def __init__(self, state_file: str, static_privatekey_hex: str = None):
        self.generate_static_key(static_privatekey_hex)
        self.state_file = state_file
        self.state = NostrestState.from_file(self.state_file)
        self.pending_keys[self.static_private_key.public_key.hex()] = self.static_private_key
        self.is_running = True
        self.poller = asyncio.create_task(self._poll())
        logger.info("My public key is: " + self.static_private_key.public_key.hex())

    async def _subscribe(self, filters):
        subscription_id = str(uuid.uuid4())
        await self.relay_manager.add_subscription(subscription_id, filters)
        request = [ClientMessageType.REQUEST, subscription_id]
        request.extend(filters.to_json_array())
        message = json.dumps(request)
        await self.relay_manager.publish_message(message)
        return subscription_id

    def _subscribe_to_static_public_key(self):
        # subscribe to all encrypted dms for me
        filter = Filter(
            kinds=[EventKind.ENCRYPTED_DIRECT_MESSAGE],
            tags={"#p": [self.static_private_key.public_key.hex()]},
        )
        if self.state.latest_event_at > 0:
            filter.since = self.state.latest_event_at
        return self._subscribe(Filters([filter]))

    def _subscribe_to_ephemeral_public_key(self, public_key_hex: str):
        return self._subscribe(Filters([Filter(
            kinds=[NOSTREST_EPHEMERAL_EVENT_KIND],
            tags={"#p": [public_key_hex]}
        )]))

    async def _close_subscription(self, subscription_id):
        await self.relay_manager.publish_message(json.dumps([ClientMessageType.CLOSE, subscription_id]))
        await self.relay_manager.close_subscription(subscription_id)

    def _send_event(self, event: Event):
        return self.relay_manager.publish_message(json.dumps([ClientMessageType.EVENT, event.to_json_object()]))

    # p2mint
    async def _send_request_and_wait_for_response(self, json_rpc_req: JsonRpcRequest, to_public_key_hex):
        private_key = PrivateKey()
        subscription_id = await self._subscribe_to_ephemeral_public_key(private_key.public_key.hex())
        event = encrypt_to_event(NOSTREST_EPHEMERAL_EVENT_KIND, json_rpc_req.to_json(), private_key, to_public_key_hex)
        async with self.lock:
            self.pending_requests[json_rpc_req.id] = NostrRequest(event, json_rpc_req)
            self.pending_keys[private_key.public_key.hex()] = private_key
        await self._send_event(event)

        sent_at = time.time()
        max_wait_time_seconds = 5
        while json_rpc_req.id in self.pending_requests.keys() and \
                self.pending_requests[json_rpc_req.id].response is None:
            if max_wait_time_seconds > 0 and time.time() - sent_at > max_wait_time_seconds:
                logger.error("Request timed out")
                break
            await asyncio.sleep(0.1)
        response_event = self.pending_requests[json_rpc_req.id].response \
            if json_rpc_req.id in self.pending_requests.keys() else None

        await self._close_subscription(subscription_id)
        async with self.lock:
            del self.pending_requests[json_rpc_req.id]
            del self.pending_keys[private_key.public_key.hex()]
        await self._send_gotit(event.id, private_key, to_public_key_hex)
        return response_event

    # p2p
    async def _send_token_and_wait_for_thx(self, token: str, private_key: PrivateKey,
                                     to_public_key_hex: str):
        # TODO: subscribe to public key derived from private_key
        subscription_id = await self._subscribe_to_ephemeral_public_key(private_key.public_key.hex())

        event = encrypt_to_event(EventKind.ENCRYPTED_DIRECT_MESSAGE, TOKEN_APP_URL_SCHEMA + token, private_key, to_public_key_hex)
        token_id = _generate_token_id(token)
        async with self.lock:
            self.pending_requests[token_id] = NostrRequest(event, TOKEN_APP_URL_SCHEMA + token)
            self.pending_keys[private_key.public_key.hex()] = private_key

        await self._send_event(event)
#        currs = ThreadPoolExecutor(max_workers=3)
#        curr_future_result = currs.submit(self._wait_for_token_thx, token_id, 0.5)
#        currs.shutdown(wait=True)
#        received = curr_future_result.result()

        started_at = time.time()
        max_wait_time_seconds = 5

        while token_id in self.pending_requests.keys() and \
                self.pending_requests[token_id].response is None:
            if max_wait_time_seconds > 0 and time.time() - started_at > max_wait_time_seconds:
                logger.warning("No thx received. How rude")
                break
            await asyncio.sleep(0.1)

        await self._close_subscription(subscription_id)

        received = self.pending_requests[token_id].response if token_id in self.pending_requests.keys() else None

        async with self.lock:
            if token_id in self.pending_requests.keys():
                del self.pending_requests[token_id]
            del self.pending_keys[private_key.public_key.hex()]

        return received if received is not None else False

    def _send_henlo(self, mint_public_key_hex):
        return self._send_request_and_wait_for_response(JsonRpcRequest(str(uuid.uuid4()), 'HENLO'),
                                                        mint_public_key_hex)

    def _send_gotit(self, event_id, private_key, mint_public_key_hex):
        return self._send_event(
            encrypt_to_event(
                NOSTREST_EPHEMERAL_EVENT_KIND,
                JsonRpcRequest(str(uuid.uuid4()), 'GOTIT', {'eventId': event_id}).to_json(),
                private_key,
                mint_public_key_hex
            )
        )

    async def _on_event(self, event_msg: EventMessage):
        if self.token_received_callback is not None and event_msg.event.kind == EventKind.ENCRYPTED_DIRECT_MESSAGE:
            self.state.latest_event_at = event_msg.event.created_at
            self.state.save(self.state_file)
            decrypted_content = decrypt_event(event_msg.event, self.static_private_key)
            if decrypted_content is not None:
                if decrypted_content.lower().startswith(TOKEN_APP_URL_SCHEMA):
                    token = decrypted_content[len(TOKEN_APP_URL_SCHEMA):]
                    token_id = _generate_token_id(token)
                    if self.token_received_callback(event_msg.event.public_key, token):
                        await self._send_encrypted_message_to(NOSTREST_EPHEMERAL_EVENT_KIND, 'thx:' + token_id,
                                                              event_msg.event.public_key)
        else:
            recipient_public_key_hex = _extract_recipient_public_key_hex_from_event(event_msg.event)
            if recipient_public_key_hex is None or recipient_public_key_hex not in self.pending_keys.keys():
                logger.error("Missing key. Cannot decrypt message")
                return

            private_key = self.pending_keys[recipient_public_key_hex]

            if event_msg.event.kind == NOSTREST_EPHEMERAL_EVENT_KIND:
                decrypted_content = decrypt_event(event_msg.event, private_key)
                if decrypted_content is not None:
                    if decrypted_content.lower().startswith('thx:'):
                        token_id = decrypted_content[4:]
                        if token_id is not None and token_id in self.pending_requests.keys():
                            async with self.lock:
                                self.pending_requests[token_id].response = True
                    else:
                        json_rpc_response = JsonRpcResponse.from_json(decrypted_content)
                        if json_rpc_response is not None and json_rpc_response.id in self.pending_requests.keys():
                            async with self.lock:
                                self.pending_requests[json_rpc_response.id].response = json_rpc_response

    def _send_encrypted_message_to(self, event_kind, message: str, to_pubkey_hex: str):
        return self._send_event(encrypt_to_event(event_kind, message, self.static_private_key, to_pubkey_hex))

    async def _rest_request(self, method: str, abs_url: str, json: dict = None, params: dict = None):
        parse_result = urlparse(abs_url)
        if parse_result.scheme != 'nostrest' or parse_result.hostname is None:
            logger.error("No nostrest url " + abs_url)
            return

        mint_public_key_hex = parse_result.hostname
        json_rpc_nostrest_params = JsonRpcNostrestParams(parse_result.path, json, params)
        json_rpc_request = JsonRpcRequest(str(uuid.uuid4()), method,
                                          dict(json_rpc_nostrest_params))
        json_rpc_response = await self._send_request_and_wait_for_response(json_rpc_request, mint_public_key_hex)

        if json_rpc_response is None:
            raise ConnectionRefusedError()

        return RestResponse(json_rpc_nostrest_params.endpoint,
                            json_rpc_response.result[
                                'httpStatus'] if 'httpStatus' in json_rpc_response.result.keys() else 502,
                            json_rpc_response.result['body'] if 'body' in json_rpc_response.result.keys() else None,
                            json_rpc_response.result['error'][
                                'message'] if 'error' in json_rpc_response.result.keys() else None)

    async def _poll(self):
        while self.is_running:
            while self.relay_manager.message_pool.has_events():
                event_msg = self.relay_manager.message_pool.get_event()
                if self._on_event:
                    await self._on_event(event_msg)
            await asyncio.sleep(0.1)

    async def _clear_relays(self):
        await self.relay_manager.clear()

    async def _set_relays(self, relay_urls: [str]):
        # add new relay urls
        for relay_url in relay_urls:
            await self.relay_manager.add_relay(relay_url)

        # use the new relays and subscribe
        await self.relay_manager.open_connections()
        # TODO: fix. this is not cool
        # time.sleep(1.25)  # allow the connections to open...

    async def henlo(self, abs_url: str, seed_relays: List[str] = []):

        parse_result = urlparse(abs_url)
        if parse_result.scheme != 'nostrest' or parse_result.hostname is None:
            logger.error("No nostrest url " + abs_url)
            return False

        mint_public_key_hex = parse_result.hostname

        await self._clear_relays()
        await self._set_relays(seed_relays)
        itsme = await self._send_henlo(mint_public_key_hex)

        if itsme is None:
            logger.error("No reply to henlo")
            return False

        if 'relays' not in itsme.result.keys() or \
                'verb' not in itsme.result.keys() or \
                itsme.result['verb'].lower() != 'itsme':
            logger.error("No itsme message")
            return False

        await self._clear_relays()
        await self._set_relays(itsme.result['relays'])
        await self._subscribe_to_static_public_key()

        return True

    async def kthxbye(self):
        await self._clear_relays()
        self.is_running = False
        await asyncio.wait([self.poller])
        del self.poller
        logger.info("Poller stopped")

    def generate_static_key(self, privatekey_hex: str = None):
        pk = bytes.fromhex(privatekey_hex) if privatekey_hex else None
        self.static_private_key = PrivateKey(pk)

    def post(self, abs_url: str, json: dict = None, params: dict = None):
        return self._rest_request('post', abs_url, json, params)

    def get(self, abs_url: str, json: dict = None, params: dict = None):
        return self._rest_request('get', abs_url, json, params)

    def send_token(self, token: str, to_pubkey_hex: str):
        return self._send_token_and_wait_for_thx(token, PrivateKey(), to_pubkey_hex)

    def send_dm(self, message: str, to_pubkey_hex: str):
        return self._send_encrypted_message_to(EventKind.ENCRYPTED_DIRECT_MESSAGE, message, to_pubkey_hex)

    def static_public_key(self):
        if self.static_private_key:
            return self.static_private_key.public_key

    def static_private_key(self):
        if self.static_private_key:
            return self.static_private_key