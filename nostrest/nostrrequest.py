from nostr.event import Event
from nostr.key import PrivateKey

from nostrest.jsonrpcish import JsonRpcRequest, JsonRpcResponse


class NostrRequest:
    event: Event
    request: any
    response: any

    def __init__(self, event: Event, request: any):
        self.event = event
        self.request = request
        self.response = None
