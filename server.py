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
from datetime import datetime, timezone
from typing import Iterator

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("SECRET_ROOMS_DB", "secret_rooms.db")
MAX_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_VIEWS = 50


# Возвращает текущий timestamp
def now_ts() -> int:
    return int(time.time())


# Переводит timestamp в ISO-формат UTC
def ts_to_iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


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


# Удаление просроченных или уже сожжённых записей
def purge_inactive_rooms(conn: sqlite3.Connection) -> int:
    cursor = conn.execute(
        "DELETE FROM rooms WHERE expires_at <= ? OR remaining_views <= 0",
        (now_ts(),),
    )
    return cursor.rowcount


# Генерация уникального room_id
def generate_room_id(conn: sqlite3.Connection) -> str:
    for _ in range(5):
        room_id = secrets.token_urlsafe(16)
        exists = conn.execute(
            "SELECT 1 FROM rooms WHERE room_id = ?",
            (room_id,),
        ).fetchone()
        if not exists:
            return room_id
    raise RuntimeError("Failed to generate unique room id")


# Базовая проверка, что строка похожа на hex
def is_hex_string(value: str) -> bool:
    if not value or len(value) % 2 != 0:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


# Общая проверка входящих данных на создание комнаты
def validate_create_request(req: "CreateRoomRequest") -> None:
    if not is_hex_string(req.ciphertext):
        raise HTTPException(status_code=400, detail="ciphertext must be valid hex")
    if not is_hex_string(req.salt):
        raise HTTPException(status_code=400, detail="salt must be valid hex")
    if req.ttl_seconds > MAX_TTL_SECONDS:
        raise HTTPException(status_code=400, detail="ttl_seconds is too large")
    if req.max_views > MAX_VIEWS:
        raise HTTPException(status_code=400, detail="max_views is too large")


# Получение комнаты из БД
def fetch_room(conn: sqlite3.Connection, room_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM rooms WHERE room_id = ?",
        (room_id,),
    ).fetchone()


# Преобразование статуса комнаты в человекочитаемый вид
def room_status(row: sqlite3.Row, now: int) -> str:
    if row["expires_at"] <= now:
        return "expired"
    if row["remaining_views"] <= 0:
        return "burned"
    return "active"


app = FastAPI(title="Secret Rooms PBKDF2", version="9.0")


# ======== Pydantic модели ========

class CreateRoomRequest(BaseModel):
    ciphertext: str = Field(..., min_length=2)
    salt: str = Field(..., min_length=2)
    ttl_seconds: int = Field(default=600, ge=1)
    max_views: int = Field(default=1, ge=1)


class CreateRoomResponse(BaseModel):
    room_id: str
    expires_at: int
    expires_at_iso: str
    remaining_views: int


class ReadRoomResponse(BaseModel):
    room_id: str
    ciphertext: str
    salt: str
    expires_at: int
    expires_at_iso: str
    remaining_views: int


class RoomMetaResponse(BaseModel):
    room_id: str
    created_at: int
    created_at_iso: str
    expires_at: int
    expires_at_iso: str
    remaining_views: int
    status: str


class StatsResponse(BaseModel):
    active_rooms: int
    server_time: int
    server_time_iso: str


@app.on_event("startup")
def startup():
    init_db()
    with db_conn() as conn:
        purge_inactive_rooms(conn)


@app.get("/")
def index():
    return {
        "service": "Secret Rooms",
        "status": "ok",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health():
    with db_conn() as conn:
        purged = purge_inactive_rooms(conn)
    return {"status": "ok", "purged": purged, "server_time": now_ts()}


@app.get("/stats", response_model=StatsResponse)
def stats():
    current_time = now_ts()
    with db_conn() as conn:
        purge_inactive_rooms(conn)
        row = conn.execute("SELECT COUNT(*) AS cnt FROM rooms").fetchone()

    return StatsResponse(
        active_rooms=row["cnt"],
        server_time=current_time,
        server_time_iso=ts_to_iso(current_time),
    )


# Создание комнаты
@app.post("/rooms", response_model=CreateRoomResponse)
def create_room(req: CreateRoomRequest):
    validate_create_request(req)
    now = now_ts()
    expires_at = now + req.ttl_seconds

    with db_conn() as conn:
        purge_inactive_rooms(conn)
        room_id = generate_room_id(conn)

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
            expires_at_iso=ts_to_iso(expires_at),
            remaining_views=req.max_views,
        )


@app.get("/rooms/{room_id}/meta", response_model=RoomMetaResponse)
def room_meta(room_id: str):
    now = now_ts()

    with db_conn() as conn:
        purge_inactive_rooms(conn)
        row = fetch_room(conn, room_id)

        if row is None:
            raise HTTPException(status_code=404, detail="Room not found")

        return RoomMetaResponse(
            room_id=row["room_id"],
            created_at=row["created_at"],
            created_at_iso=ts_to_iso(row["created_at"]),
            expires_at=row["expires_at"],
            expires_at_iso=ts_to_iso(row["expires_at"]),
            remaining_views=row["remaining_views"],
            status=room_status(row, now),
        )


# Получение ciphertext (с учётом TTL и burn-after-read)
@app.get("/rooms/{room_id}", response_model=ReadRoomResponse)
def read_room(room_id: str):
    now = now_ts()

    with db_conn() as conn:
        row = fetch_room(conn, room_id)

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
            expires_at_iso=ts_to_iso(row["expires_at"]),
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
    margin: 0;
}

.card {
    background: #1e293b;
    padding: 32px;
    border-radius: 12px;
    width: 420px;
    box-shadow: 0 0 40px rgba(0, 0, 0, 0.4);
}

h2 {
    margin-bottom: 10px;
}

p {
    color: #94a3b8;
    font-size: 14px;
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
    margin-top: 12px;
    border-radius: 6px;
    border: none;
    background: #2563eb;
    color: white;
    cursor: pointer;
}

button:hover {
    background: #1d4ed8;
}

button.secondary {
    background: #334155;
}

button.secondary:hover {
    background: #475569;
}

.meta {
    margin-top: 16px;
    font-size: 14px;
    color: #cbd5e1;
    line-height: 1.6;
}

#status {
    margin-top: 16px;
    font-size: 14px;
    color: #fbbf24;
}

#secret {
    margin-top: 20px;
    background: #0f172a;
    padding: 12px;
    border-radius: 6px;
    word-break: break-word;
    box-sizing: border-box;
    min-height: 44px;
}
</style>
</head>
<body>
<div class="card">
<h2>Secret Room</h2>
<p>Введите пароль, чтобы расшифровать секрет локально в браузере.</p>
<input type="password" id="password" placeholder="Enter password">
<button class="secondary" onclick="togglePassword()">Показать / скрыть пароль</button>
<button id="decryptBtn" onclick="decryptSecret()">Decrypt</button>
<div class="meta" id="meta">Загрузка информации о комнате...</div>
<div id="status"></div>
<div id="secret"></div>
<button class="secondary" id="copyBtn" onclick="copySecret()" style="display:none;">Скопировать секрет</button>
</div>

<script>
const roomId = "__ROOM_ID__";
let secretText = "";
let expiresAt = null;

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

function setStatus(text) {
    document.getElementById("status").innerText = text;
}

function togglePassword() {
    const input = document.getElementById("password");
    input.type = input.type === "password" ? "text" : "password";
}

function updateCountdown() {
    if (!expiresAt) {
        return;
    }

    const secondsLeft = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
    const meta = document.getElementById("meta");
    const parts = meta.innerText.split("\\n").slice(0, 3);
    parts.push("Осталось секунд до истечения: " + secondsLeft);
    meta.innerText = parts.join("\\n");
}

async function loadMeta() {
    try {
        const resp = await fetch("/rooms/" + roomId + "/meta");
        if (!resp.ok) {
            document.getElementById("meta").innerText = "Комната не найдена или уже удалена.";
            document.getElementById("decryptBtn").disabled = true;
            return;
        }

        const data = await resp.json();
        expiresAt = data.expires_at;
        document.getElementById("meta").innerText =
            "Создана: " + new Date(data.created_at * 1000).toLocaleString() + "\\n" +
            "Истекает: " + new Date(data.expires_at * 1000).toLocaleString() + "\\n" +
            "Осталось просмотров: " + data.remaining_views;
        updateCountdown();
    } catch (e) {
        document.getElementById("meta").innerText = "Не удалось загрузить метаданные комнаты.";
    }
}

async function decryptSecret() {
    const password = document.getElementById("password").value;
    if (!password) {
        setStatus("Введите пароль.");
        return;
    }

    setStatus("Идёт расшифровка...");

    try {
        const resp = await fetch("/rooms/" + roomId);
        if (!resp.ok) {
            document.getElementById("secret").innerText = "Secret expired or burned.";
            setStatus("Комната уже недоступна.");
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
        secretText = decoder.decode(decrypted);
        document.getElementById("secret").innerText = secretText;
        document.getElementById("copyBtn").style.display = "block";
        setStatus("Секрет расшифрован локально. При следующем чтении просмотров станет меньше.");
        expiresAt = data.expires_at;
        updateCountdown();
    } catch (e) {
        document.getElementById("secret").innerText = "Decryption failed.";
        setStatus("Проверьте пароль и попробуйте ещё раз.");
    }
}

async function copySecret() {
    if (!secretText) {
        return;
    }

    try {
        await navigator.clipboard.writeText(secretText);
        setStatus("Секрет скопирован в буфер обмена.");
    } catch (e) {
        setStatus("Не удалось скопировать секрет.");
    }
}

loadMeta();
setInterval(updateCountdown, 1000);
</script>
</body>
</html>
"""

    return HTMLResponse(html.replace("__ROOM_ID__", room_id))