import ssl
import threading
import uuid
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
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives import hashes

from nostrest.event_utils import encrypt_to_event, decrypt_event, NOSTREST_EPHEMERAL_EVENT_KIND
from nostrest.jsonrpcish import JsonRpcRequest, JsonRpcResponse, JsonRpcNostrestParams
from nostrest.nostrrequest import NostrRequest
from typing import Callable

from nostrest.restresponse import RestResponse


def generate_token_id(token: str):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(token, 'utf-8'))
    return base64.b64encode(digest.finalize()[0:8]).decode('utf-8').replace('=', '')


class Nostrest:
    relay_manager: RelayManager = RelayManager()
    pending_requests: dict[str, NostrRequest] = {}
    static_private_key: PrivateKey
    poller: threading.Thread
    mint_public_key: str
    token_received_callback: Callable[[str, str], bool]
    is_running: bool = False

    def __init__(self, static_privatekey_hex: str = None):
        self.generate_static_key(static_privatekey_hex)
        self.lock = threading.Lock()
        print("my public key is: " + self.static_private_key.public_key.hex())

    def subscribe(self):
        # subscribe to all encrypted dms for me
        filters = Filters(
            [
                Filter(
                    kinds=[EventKind.ENCRYPTED_DIRECT_MESSAGE, NOSTREST_EPHEMERAL_EVENT_KIND],
                    tags={"#p": [self.static_private_key.public_key.hex()]},
                    limit=0
                )
            ]
        )
        subscription_id = str(uuid.uuid4())
        self.relay_manager.add_subscription(subscription_id, filters)

        request = [ClientMessageType.REQUEST, subscription_id]
        request.extend(filters.to_json_array())
        message = json.dumps(request)
        self.relay_manager.publish_message(message)
        return subscription_id

    def send_event(self, event: Event):
        self.relay_manager.publish_message(json.dumps([ClientMessageType.EVENT, event.to_json_object()]))

    def send_request_and_wait_for_response(self, json_rpc_req: JsonRpcRequest, private_key: PrivateKey,
                                           to_public_key_hex):
        event = encrypt_to_event(NOSTREST_EPHEMERAL_EVENT_KIND, json_rpc_req.to_json(), private_key, to_public_key_hex)
        with self.lock:
            self.pending_requests[json_rpc_req.id] = NostrRequest(private_key, event, json_rpc_req)
        self.send_event(event)
        currs = ThreadPoolExecutor(max_workers=3)
        curr_future_result = currs.submit(self.wait_for_result, json_rpc_req.id, 2)
        currs.shutdown(wait=True)
        response_event = curr_future_result.result()
        with self.lock:
            del self.pending_requests[json_rpc_req.id]
        return response_event

    def wait_for_result(self, json_rpc_req_id, max_wait_time_seconds: int = 0):
        started_at = time.time()
        while json_rpc_req_id in self.pending_requests.keys() and \
                self.pending_requests[json_rpc_req_id].response is None:
            if max_wait_time_seconds > 0 and time.time() - started_at > max_wait_time_seconds:
                print("request timed out")
                break
            time.sleep(0.1)
        return self.pending_requests[json_rpc_req_id].response \
            if json_rpc_req_id in self.pending_requests.keys() else None

    def send_token_and_wait_for_received(self, token: str, private_key: PrivateKey,
                                         to_public_key_hex: str):
        event = encrypt_to_event(EventKind.ENCRYPTED_DIRECT_MESSAGE, 'cashu://' + token, private_key, to_public_key_hex)
        token_id = generate_token_id(token)
        with self.lock:
            self.pending_requests[token_id] = NostrRequest(private_key, event, 'cashu://' + token)
        self.send_event(event)
        currs = ThreadPoolExecutor(max_workers=3)
        curr_future_result = currs.submit(self.wait_for_token_thx, token_id, 0.5)
        currs.shutdown(wait=True)
        received = curr_future_result.result()
        with self.lock:
            del self.pending_requests[token_id]
        return received

    def wait_for_token_thx(self, token_id, max_wait_time_seconds: int = 0):
        started_at = time.time()
        while token_id in self.pending_requests.keys() and \
                self.pending_requests[token_id].response is None:
            if max_wait_time_seconds > 0 and time.time() - started_at > max_wait_time_seconds:
                print("No thx received. How rude")
                break
            time.sleep(0.1)

        if token_id not in self.pending_requests.keys():
            return False

        if self.pending_requests[token_id].response is None:
            return False

        return self.pending_requests[token_id].response

    def send_henlo(self):
        return self.send_request_and_wait_for_response(JsonRpcRequest('ididid', 'HENLO'), self.static_private_key,
                                                       self.mint_public_key)

    def start(self, mint_public_key: str, seed_relays: List[str] = [],
              token_received_callback: Callable[[str, str], bool] = None):
        self.mint_public_key = mint_public_key
        self.token_received_callback = token_received_callback
        self.poller = threading.Thread(
            target=self.poll,
            args=(
                self.on_event,
            ),
        )
        self.is_running = True
        self.poller.start()

        for relay in seed_relays:
            self.relay_manager.add_relay(relay)
        self.relay_manager.open_connections()

        # TODO: fix. this is not cool
        time.sleep(1.25)  # allow the connections to open...

        self.subscribe()
        itsme = self.send_henlo()

        if itsme is None:
            print("no reply to henlo")
            return False

        if 'relays' not in itsme.result.keys() or \
                'verb' not in itsme.result.keys() or \
                itsme.result['verb'].lower() != 'itsme':
            print("no itsme message")
            return False

        self.relay_manager.close_connections()
        # remove old relay urls
        self.relay_manager.relays.clear()

        # add new relay urls
        for relay_url in itsme.result['relays']:
            self.relay_manager.add_relay(relay_url)

        # use the new relays and subscribe
        self.relay_manager.open_connections()
        # TODO: fix. this is not cool
        time.sleep(1.25)  # allow the connections to open...
        self.subscribe()

        return True

    def stop(self):
        self.is_running = False
        self.poller.join()
        print("poller stopped")
        self.relay_manager.close_connections()

    def on_event(self, event_msg: EventMessage):
        if self.token_received_callback is not None and event_msg.event.kind == EventKind.ENCRYPTED_DIRECT_MESSAGE:
            decrypted_content = decrypt_event(event_msg.event, self.static_private_key)
            if decrypted_content is not None:
                if decrypted_content.lower().startswith('cashu://'):
                    token = decrypted_content[8:]
                    token_id = generate_token_id(token)
                    if self.token_received_callback(event_msg.event.public_key, token):
                        self.send_encrypted_message_to( NOSTREST_EPHEMERAL_EVENT_KIND, 'thx:' + token_id, event_msg.event.public_key)
        else:
            if event_msg.event.kind == NOSTREST_EPHEMERAL_EVENT_KIND:
                decrypted_content = decrypt_event(event_msg.event, self.static_private_key)
                if decrypted_content is not None:
                    if decrypted_content.lower().startswith('thx:'):
                        token_id = decrypted_content[4:]
                        if token_id is not None and token_id in self.pending_requests.keys():
                            with self.lock:
                                self.pending_requests[token_id].response = True
                    else:
                        json_rpc_response = JsonRpcResponse.from_json(decrypted_content)
                        if json_rpc_response is not None and json_rpc_response.id in self.pending_requests.keys():
                            with self.lock:
                                self.pending_requests[json_rpc_response.id].response = json_rpc_response

    def generate_static_key(self, privatekey_hex: str = None):
        pk = bytes.fromhex(privatekey_hex) if privatekey_hex else None
        self.static_private_key = PrivateKey(pk)

    def send_encrypted_message_to(self, event_kind, message: str, to_pubkey_hex: str):
        event = encrypt_to_event(event_kind, message, self.static_private_key, to_pubkey_hex)
        self.send_event(event)

    def post(self, rel_url: str, json: dict = None, params: dict = None):
        return self.__rest_request('post', rel_url, json, params)

    def get(self, rel_url: str, json: dict = None, params: dict = None):
        return self.__rest_request('get', rel_url, json, params)

    def send_token(self, token: str, to_pubkey_hex: str):
        return self.send_token_and_wait_for_received(token, self.static_private_key, to_pubkey_hex)

    def send_dm(self, message: str, to_pubkey_hex: str):
        return self.send_encrypted_message_to(EventKind.ENCRYPTED_DIRECT_MESSAGE, message, to_pubkey_hex)

    def __rest_request(self, method: str, rel_url: str, json: dict = None, params: dict = None):
        parse_result = urlparse(rel_url)
        json_rpc_request = JsonRpcRequest(str(uuid.uuid4()), method,
                                          JsonRpcNostrestParams(parse_result.path, json, params))
        json_rpc_response = self.send_request_and_wait_for_response(json_rpc_request, self.static_private_key,
                                                                    self.mint_public_key)

        return RestResponse(json_rpc_request.params.endpoint,
                            json_rpc_response.result[
                                'httpStatus'] if 'httpStatus' in json_rpc_response.result.keys() else 502,
                            json_rpc_response.result['body'] if 'body' in json_rpc_response.result.keys() else None,
                            json_rpc_response.result['error'][
                                'message'] if 'error' in json_rpc_response.result.keys() else None) if json_rpc_response is not None else None

    def poll(self, callback_func=None):
        while self.is_running:
            while self.relay_manager.message_pool.has_events():
                event_msg = self.relay_manager.message_pool.get_event()
                if callback_func:
                    callback_func(event_msg)
            time.sleep(0.1)
