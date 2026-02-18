from __future__ import annotations

"""
Secret Rooms — серверная часть.

Основная идея:
- Сервер НИКОГДА не знает пароль.
- Сервер хранит только:
    - ciphertext (зашифрованные данные)
    - salt (для вывода ключа)
    - TTL
    - количество оставшихся просмотров

Расшифровка происходит полностью в браузере.
"""

import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

DB_PATH = os.environ.get("SECRET_ROOMS_DB", "secret_rooms.db")


# Возвращает текущий timestamp
def now_ts() -> int:
    return int(time.time())


# Контекстный менеджер для работы с SQLite
@contextmanager
def db_conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# Инициализация базы данных
def init_db() -> None:
    with db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rooms (
                room_id TEXT PRIMARY KEY,
                ciphertext TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                remaining_views INTEGER NOT NULL
            );
            """
        )


app = FastAPI(title="Secret Rooms PBKDF2", version="8.0")


# ======== Pydantic модели ========

class CreateRoomRequest(BaseModel):
    ciphertext: str
    salt: str
    ttl_seconds: int = 600
    max_views: int = 1


class CreateRoomResponse(BaseModel):
    room_id: str
    expires_at: int
    remaining_views: int


class ReadRoomResponse(BaseModel):
    room_id: str
    ciphertext: str
    salt: str
    expires_at: int
    remaining_views: int


@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


# Создание комнаты
@app.post("/rooms", response_model=CreateRoomResponse)
def create_room(req: CreateRoomRequest):
    now = now_ts()
    expires_at = now + req.ttl_seconds

    with db_conn() as conn:
        room_id = secrets.token_urlsafe(16)

        conn.execute(
            """
            INSERT INTO rooms(room_id, ciphertext, salt, created_at, expires_at, remaining_views)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (room_id, req.ciphertext, req.salt, now, expires_at, req.max_views),
        )

        return CreateRoomResponse(
            room_id=room_id,
            expires_at=expires_at,
            remaining_views=req.max_views,
        )


# Получение ciphertext (с учётом TTL и burn-after-read)
@app.get("/rooms/{room_id}", response_model=ReadRoomResponse)
def read_room(room_id: str):
    now = now_ts()

    with db_conn() as conn:
        row = conn.execute(
            "SELECT * FROM rooms WHERE room_id = ?",
            (room_id,),
        ).fetchone()

        if row is None:
            raise HTTPException(status_code=404, detail="Room not found")

        # Проверка TTL и просмотров
        if row["expires_at"] <= now or row["remaining_views"] <= 0:
            conn.execute("DELETE FROM rooms WHERE room_id = ?", (room_id,))
            raise HTTPException(status_code=410, detail="Expired or burned")

        new_remaining = row["remaining_views"] - 1

        if new_remaining <= 0:
            conn.execute("DELETE FROM rooms WHERE room_id = ?", (room_id,))
        else:
            conn.execute(
                "UPDATE rooms SET remaining_views = ? WHERE room_id = ?",
                (new_remaining, room_id),
            )

        return ReadRoomResponse(
            room_id=row["room_id"],
            ciphertext=row["ciphertext"],
            salt=row["salt"],
            expires_at=row["expires_at"],
            remaining_views=new_remaining,
        )


# HTML-страница просмотра
@app.get("/view/{room_id}", response_class=HTMLResponse)
def view_room(room_id: str):

    html = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Secret Rooms</title>
<style>
body {
    background: #0f172a;
    color: #e2e8f0;
    font-family: Arial, sans-serif;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
}

.card {
    background: #1e293b;
    padding: 40px;
    border-radius: 12px;
    width: 400px;
    box-shadow: 0 0 40px rgba(0,0,0,0.4);
}

h2 {
    margin-bottom: 20px;
}

input {
    width: 100%;
    padding: 10px;
    margin-top: 10px;
    border-radius: 6px;
    border: none;
    box-sizing: border-box; 
}

button {
    width: 100%;
    padding: 12px;
    margin-top: 15px;
    border-radius: 6px;
    border: none;
    background: #2563eb;
    color: white;
    cursor: pointer;
}

button:hover {
    background: #1d4ed8;
}

#secret {
    margin-top: 20px;
    background: #0f172a;
    padding: 12px;
    border-radius: 6px;
    word-break: break-word;
    box-sizing: border-box; 
</style>
</head>
<body>
<div class="card">
<h2>Secret Room</h2>
<input type="password" id="password" placeholder="Enter password">
<button onclick="decryptSecret()">Decrypt</button>
<div id="secret"></div>
</div>

<script>

const roomId = "__ROOM_ID__";

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

async function deriveKey(password, saltBytes) {
    const enc = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 200000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );
}

async function decryptSecret() {

    const password = document.getElementById("password").value;
    if (!password) return;

    try {
        const resp = await fetch("/rooms/" + roomId);
        if (!resp.ok) {
            document.getElementById("secret").innerText = "Secret expired or burned.";
            return;
        }

        const data = await resp.json();

        const payload = hexToBytes(data.ciphertext);
        const salt = hexToBytes(data.salt);

        const iv = payload.slice(0, 12);
        const ciphertext = payload.slice(12);

        const key = await deriveKey(password, salt);

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );

        const decoder = new TextDecoder();
        document.getElementById("secret").innerText =
            decoder.decode(decrypted);

    } catch (e) {
        document.getElementById("secret").innerText =
            "Decryption failed.";
    }
}

</script>
</body>
</html>
"""

    return HTMLResponse(html.replace("__ROOM_ID__", room_id))