import websocket

from nostrest.nostrest import Nostrest
from nostr.event import Event
from nostr.key import PublicKey
import asyncio
import threading

# https://github.com/monty888/nostrpy/blob/master/cmd_event_view.py

seed_relays = [
    "wss://nostr-pub.wellorder.net",
    "wss://relay.damus.io",
    "wss://nostr.onsats.org",
#    "wss://nostr-relay.wlvs.space",
#    "wss://nostr.bitcoiner.social",
#    "wss://relay.nostr.info",
#    "wss://nostr-pub.semisol.dev",
#    "wss://nostr.rocks"
]


# websocket.enableTrace(True)

def cb(from_pubkey_hex: str, messsage: str):
    print("Message from "+from_pubkey_hex+": "+messsage)

#async def main():
nostrest = Nostrest(static_privatekey_hex="8f27ea9abe6345d9276c0881b85dca6ff16188dc71d8abefd04a944e8a80e203")

nostrest.start(
    mint_public_key="8e70c70ceff84b8ff2b95bc35f12f766c24bca06256beb07846b736a0fa6cb99",
    seed_relays=seed_relays,
    direct_message_callback=cb
)
resp = nostrest.get('/keys')
if resp:
    resp.raise_for_status()
    body = resp.json()
    print(body)

resp = nostrest.get('/keysets')
if resp:
    resp.raise_for_status()
    body = resp.json()
    print(body)

nostrest.stop()
#asyncio.run(main())

