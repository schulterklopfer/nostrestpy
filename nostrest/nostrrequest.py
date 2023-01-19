from nostr.event import Event
from nostr.key import PrivateKey

from nostrest.jsonrpcish import JsonRpcRequest, JsonRpcResponse


class NostrRequest:
    private_key: PrivateKey
    event: Event
    request: any
    response: any

    def __init__(self, private_key: PrivateKey, event: Event, request: any):
        self.private_key = private_key
        self.event = event
        self.request = request
        self.response = None
