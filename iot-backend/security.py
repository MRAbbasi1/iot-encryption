import os
import json
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

secret_key_hex = os.getenv("AES_SECRET_KEY")
if not secret_key_hex:
    raise ValueError("AES_SECRET_KEY is missing in .env file!")

KEY_BYTES = binascii.unhexlify(secret_key_hex)
aesgcm = AESGCM(KEY_BYTES)

def decrypt_iot_payload(iv_hex: str, ciphertext_hex: str, tag_hex: str) -> dict:
    try:
        iv_bytes = binascii.unhexlify(iv_hex)
        ciphertext_bytes = binascii.unhexlify(ciphertext_hex)
        tag_bytes = binascii.unhexlify(tag_hex)

        data_to_decrypt = ciphertext_bytes + tag_bytes
        decrypted_bytes = aesgcm.decrypt(iv_bytes, data_to_decrypt, None)

        decrypted_str = decrypted_bytes.decode('utf-8')
        return json.loads(decrypted_str)

    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format after decryption")
    except Exception:
        raise ValueError("Decryption failed or data tampered")