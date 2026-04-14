from __future__ import annotations

"""
Secret Rooms — клиентская часть.

Что делает клиент:
1. Принимает секрет и пароль.
2. Выводит ключ через PBKDF2.
3. Шифрует данные AES-GCM.
4. Отправляет только ciphertext + salt на сервер.
"""

import argparse
import os
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from urllib.parse import urlparse

import qrcode
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_SERVER = "http://127.0.0.1:8000"


# Вывод ключа из пароля
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


# Шифрование секрета
def encrypt_secret(secret: str, password: str) -> tuple[str, str]:
    salt = os.urandom(16)
    key = derive_key(password, salt)

    iv = os.urandom(12)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(iv, secret.encode(), None)
    payload = iv + ciphertext

    return salt.hex(), payload.hex()


def format_ts(ts: int) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone()
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def validate_positive(value: int, name: str) -> None:
    if value <= 0:
        raise ValueError(f"{name} должен быть больше нуля.")


def read_secret_from_args(args) -> str:
    if args.secret_text is not None:
        return args.secret_text

    if args.secret_file is not None:
        try:
            return Path(args.secret_file).read_text(encoding="utf-8").rstrip("\n")
        except OSError as exc:
            raise ValueError(f"Не удалось прочитать файл секрета: {exc}") from exc

    return getpass("Введите секрет: ")


def prompt_password(confirm: bool = False) -> str:
    password = getpass("Введите пароль: ")
    if not confirm:
        return password

    password_again = getpass("Повторите пароль: ")
    if password != password_again:
        raise ValueError("Пароли не совпадают.")
    return password


def ensure_server_available(server: str) -> None:
    try:
        r = requests.get(f"{server}/health", timeout=5)
        r.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"Сервер недоступен: {exc}") from exc


def build_view_url(server: str, room_id: str) -> str:
    return f"{server.rstrip('/')}/view/{room_id}"


def extract_room_parts(server: str, room_ref: str) -> tuple[str, str]:
    room_ref = room_ref.strip()

    if room_ref.startswith("http://") or room_ref.startswith("https://"):
        parsed = urlparse(room_ref)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 2 and parts[-2] == "view":
            return f"{parsed.scheme}://{parsed.netloc}", parts[-1]
        raise ValueError("Ожидалась ссылка вида http://host/view/<room_id>.")

    return server.rstrip("/"), room_ref


def print_room_summary(room_url: str, expires_at: int, remaining_views: int) -> None:
    print("\nКомната создана успешно:")
    print(room_url)
    print(f"Истекает: {format_ts(expires_at)}")
    print(f"Осталось просмотров: {remaining_views}")


def print_qr(token: str) -> None:
    print("\nQR:\n")
    qr = qrcode.QRCode(border=1)
    qr.add_data(token)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


def cmd_create(args):
    server = args.server.rstrip("/")

    try:
        validate_positive(args.ttl, "TTL")
        validate_positive(args.views, "Количество просмотров")
        secret = read_secret_from_args(args)
        password = prompt_password(confirm=not args.no_confirm_password)
    except ValueError as exc:
        print(exc)
        return 1

    if not secret or not password:
        print("Секрет и пароль обязательны.")
        return 1

    try:
        ensure_server_available(server)
    except RuntimeError as exc:
        print(exc)
        return 1

    salt_hex, ciphertext_hex = encrypt_secret(secret, password)

    try:
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
        r.raise_for_status()
    except requests.HTTPError:
        print("Ошибка сервера:", r.text)
        return 1
    except requests.RequestException as exc:
        print("Не удалось создать комнату:", exc)
        return 1

    data = r.json()
    room_url = build_view_url(server, data["room_id"])

    print_room_summary(
        room_url=room_url,
        expires_at=data["expires_at"],
        remaining_views=data["remaining_views"],
    )

    if args.qr:
        print_qr(room_url)

    return 0


def cmd_info(args):
    try:
        server, room_id = extract_room_parts(args.server, args.room)
        ensure_server_available(server)
        r = requests.get(f"{server}/rooms/{room_id}/meta", timeout=10)
        r.raise_for_status()
    except ValueError as exc:
        print(exc)
        return 1
    except requests.HTTPError:
        print("Ошибка сервера:", r.text)
        return 1
    except requests.RequestException as exc:
        print("Не удалось получить информацию о комнате:", exc)
        return 1

    data = r.json()
    print("\nИнформация о комнате:")
    print(f"Room ID: {data['room_id']}")
    print(f"Ссылка: {build_view_url(server, room_id)}")
    print(f"Создана: {format_ts(data['created_at'])}")
    print(f"Истекает: {format_ts(data['expires_at'])}")
    print(f"Осталось просмотров: {data['remaining_views']}")
    print(f"Статус: {data['status']}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Secret Rooms CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create", help="Создать новую секретную комнату")
    c.add_argument("--server", default=DEFAULT_SERVER)
    c.add_argument("--ttl", type=int, default=600)
    c.add_argument("--views", type=int, default=1)
    c.add_argument("--qr", action="store_true")
    c.add_argument("--secret-text", help="Передать секрет напрямую аргументом")
    c.add_argument("--secret-file", help="Прочитать секрет из UTF-8 файла")
    c.add_argument(
        "--no-confirm-password",
        action="store_true",
        help="Не спрашивать повторное подтверждение пароля",
    )
    c.set_defaults(func=cmd_create)

    i = sub.add_parser("info", help="Показать метаданные комнаты без чтения секрета")
    i.add_argument("room", help="room_id или ссылка вида http://host/view/<room_id>")
    i.add_argument("--server", default=DEFAULT_SERVER)
    i.set_defaults(func=cmd_info)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())