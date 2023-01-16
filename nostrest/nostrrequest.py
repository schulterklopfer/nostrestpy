from nostr.event import Event
from nostr.key import PrivateKey

from nostrest.jsonrpcish import JsonRpcRequest, JsonRpcResponse


class NostrRequest:
    private_key: PrivateKey
    event: Event
    json_rpc_request: JsonRpcRequest
    json_rpc_response: JsonRpcResponse

    def __init__(self, private_key: PrivateKey, event: Event, json_rpc_request: JsonRpcRequest):
        self.private_key = private_key
        self.event = event
        self.json_rpc_request = json_rpc_request
        self.json_rpc_response = None
