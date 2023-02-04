import websocket

from nostrest.nostrest import Nostrest
from nostr.event import Event
from nostr.key import PublicKey
import asyncio
import threading

# https://github.com/monty888/nostrpy/blob/master/cmd_event_view.py

seed_relays = [
    "wss://relay.snort.social",
    "wss://nostr-pub.wellorder.net"
#    "wss://relay.damus.io"
#    "wss://nostr.onsats.org",
    #    "wss://nostr-relay.wlvs.space",
    #    "wss://nostr.bitcoiner.social",
    #    "wss://relay.nostr.info",
    #    "wss://nostr-pub.semisol.dev",
    #    "wss://nostr.rocks"
]


# websocket.enableTrace(True)

def cb(from_pubkey_hex: str, messsage: str) -> bool:
    print("Message from " + from_pubkey_hex + ": " + messsage)
    return True


async def main():
    nostrest = Nostrest(
        state_file='./nostrest_state.json',
        static_privatekey_hex="8f27ea9abe6345d9276c0881b85dca6ff16188dc71d8abefd04a944e8a80e203",
    )

    nostrest.token_received_callback = cb

    # use this to look for mint and sync common relays by sending henlo through a bunch of seed relays
    synced = await nostrest.henlo(
        abs_url='nostrest://8e70c70ceff84b8ff2b95bc35f12f766c24bca06256beb07846b736a0fa6cb99',
        seed_relays=seed_relays,
    )

#   # use this to look for different mint and sync common relays by sending henlo through a bunch of seed relays
#    await nostrest.henlo(
#        abs_url='nostrest://8e70c70ceff84b8ff2b95bc35f12f766c24bca06256beb07846b736a0fa6cb99',
#        seed_relays=seed_relays,
#    )

    resp = await nostrest.get('nostrest://8e70c70ceff84b8ff2b95bc35f12f766c24bca06256beb07846b736a0fa6cb99/keys')
    if resp:
        resp.raise_for_status()
        body = resp.json()
        print(body)

    resp = await nostrest.get('nostrest://8e70c70ceff84b8ff2b95bc35f12f766c24bca06256beb07846b736a0fa6cb99/keysets')
    if resp:
        resp.raise_for_status()
        body = resp.json()
        print(body)

    received = await nostrest.send_token('token', 'b9b8a9749442726a99b2e6d194d14d907857a10786ae0c47f79a07c31149e27d')

    await nostrest.kthxbye()

asyncio.run(main())
