import base64
from loguru import logger
from nostr.event import Event
from nostr.key import PublicKey, PrivateKey
from nostr.message_pool import EventMessage

from nostrest import cbc

NOSTREST_EPHEMERAL_EVENT_KIND = 23338

def decrypt_event(event: Event, private_key: PrivateKey):
    if "?iv=" in event.content:
        try:
            shared_secret = private_key.compute_shared_secret(
                event.public_key
            )
            # print("shared secret: ", shared_secret.hex())
            # print("plain text:", message)
            aes = cbc.AESCipher(key=shared_secret)
            enc_text_b64, iv_b64 = event.content.split("?iv=")
            iv = base64.decodebytes(iv_b64.encode("utf-8"))
            enc_text = base64.decodebytes(enc_text_b64.encode("utf-8"))
            # print("decrypt iv: ", iv)
            return aes.decrypt(iv, enc_text)
            # print(f"From {event.public_key[:5]}...: {dec_text}")
        except:
            logger.error("Unable to decrypt message.")
            return None

def encrypt_to_event(event_kind: int, message: str, private_key: PrivateKey, to_public_key_hex: str):
    public_key_hex = private_key.public_key.hex()
    shared_secret = private_key.compute_shared_secret(to_public_key_hex)
    aes = cbc.AESCipher(key=shared_secret)
    iv, enc_text = aes.encrypt(message)
    content = f"{base64.b64encode(enc_text).decode('utf-8')}?iv={base64.b64encode(iv).decode('utf-8')}"
    event = Event(
        public_key_hex,
        content,
        tags=[["p", to_public_key_hex]],
        kind=event_kind,
    )
    event.sign(private_key.hex())
    return event