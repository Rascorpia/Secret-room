"""
Secret Rooms — клиентская часть.

Что делает клиент:
1. Принимает секрет и пароль.
2. Выводит ключ через PBKDF2.
3. Шифрует данные AES-GCM.
4. Отправляет только ciphertext + salt на сервер.
"""

from __future__ import annotations

import argparse
import os
import requests
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import qrcode

DEFAULT_SERVER = "http://127.0.0.1:8000"


# Вывод ключа из пароля
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Шифрование секрета
def encrypt_secret(secret: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)

    iv = os.urandom(12)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(iv, secret.encode(), None)
    payload = iv + ciphertext

    return salt.hex(), payload.hex()


def cmd_create(args):
    server = args.server.rstrip("/")

    secret = getpass("Введите секрет: ")
    password = getpass("Введите пароль: ")

    if not secret or not password:
        print("Секрет и пароль обязательны.")
        return 1

    salt_hex, ciphertext_hex = encrypt_secret(secret, password)

    r = requests.post(
        f"{server}/rooms",
        json={
            "ciphertext": ciphertext_hex,
            "salt": salt_hex,
            "ttl_seconds": args.ttl,
            "max_views": args.views,
        },
        timeout=10,
    )

    if r.status_code != 200:
        print("Ошибка сервера:", r.text)
        return 1

    room_id = r.json()["room_id"]

    token = f"{server}/view/{room_id}"

    print("\nКомната создана:")
    print(token)

    if args.qr:
        print("\nQR:\n")
        qr = qrcode.QRCode(border=1)
        qr.add_data(token)
        qr.make(fit=True)
        qr.print_ascii(invert=True)

    return 0


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create")
    c.add_argument("--server", default=DEFAULT_SERVER)
    c.add_argument("--ttl", type=int, default=600)
    c.add_argument("--views", type=int, default=1)
    c.add_argument("--qr", action="store_true")
    c.set_defaults(func=cmd_create)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())