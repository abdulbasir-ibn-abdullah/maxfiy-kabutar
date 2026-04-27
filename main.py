"""
Ephemeral E2EE Chat Server
- No persistence: everything lives in RAM only
- Server only relays ciphertext, never sees plaintext
- Messages auto-delete 60s after delivery
- Rooms auto-close if no second user joins within 10 min
- Max 10 users per room, min 2
"""

import asyncio
import hashlib
import hmac
import json
import os
import time
import uuid
from collections import defaultdict
from typing import Optional

import argon2
from argon2 import PasswordHasher
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)

ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)

# ── In-memory state (no disk, no DB) ──────────────────────────────────────────

class Room:
    def __init__(self, room_id: str, name: str, password_hash: str):
        self.id = room_id
        self.name = name
        self.password_hash = password_hash
        self.created_at = time.time()
        self.connections: dict[str, WebSocket] = {}   # user_id → ws
        self.usernames: dict[str, str] = {}            # user_id → display name
        self.pending_messages: list[dict] = []         # undelivered msgs
        self.empty_timer_task: Optional[asyncio.Task] = None
        self.active = True

    def user_count(self) -> int:
        return len(self.connections)

    def verify_password(self, password: str) -> bool:
        try:
            return ph.verify(self.password_hash, password)
        except argon2.exceptions.VerifyMismatchError:
            return False


ROOMS: dict[str, Room] = {}          # room_id → Room
MESSAGE_EXPIRY: list[tuple] = []      # (expire_at, room_id, msg_id)

# ── REST endpoints ─────────────────────────────────────────────────────────────

class CreateRoomRequest(BaseModel):
    name: str
    password: str


class JoinRoomRequest(BaseModel):
    room_id: str
    password: str


@app.post("/api/room/create")
async def create_room(req: CreateRoomRequest):
    if not req.name.strip() or not req.password:
        raise HTTPException(400, "Name and password required")
    if len(req.password) < 4:
        raise HTTPException(400, "Password must be at least 4 characters")

    room_id = str(uuid.uuid4())[:8].upper()
    while room_id in ROOMS:
        room_id = str(uuid.uuid4())[:8].upper()

    password_hash = ph.hash(req.password)
    room = Room(room_id, req.name.strip(), password_hash)
    ROOMS[room_id] = room

    # Start 10-minute lonely-room timer
    room.empty_timer_task = asyncio.create_task(
        _lonely_room_timer(room_id)
    )

    return {"room_id": room_id, "room_name": room.name}


@app.post("/api/room/join")
async def join_room(req: JoinRoomRequest):
    room = ROOMS.get(req.room_id.upper())
    if not room or not room.active:
        raise HTTPException(404, "Room not found")
    if room.user_count() >= 10:
        raise HTTPException(400, "Room is full (max 10 users)")
    if not room.verify_password(req.password):
        raise HTTPException(403, "Wrong password")

    return {"room_id": room.id, "room_name": room.name}


# ── WebSocket ──────────────────────────────────────────────────────────────────

@app.websocket("/ws/{room_id}/{user_id}/{username}")
async def websocket_endpoint(
    websocket: WebSocket,
    room_id: str,
    user_id: str,
    username: str,
):
    room = ROOMS.get(room_id)
    if not room or not room.active:
        await websocket.close(code=4004, reason="Room not found")
        return

    if room.user_count() >= 10:
        await websocket.close(code=4029, reason="Room full")
        return

    await websocket.accept()

    # Register user
    room.connections[user_id] = websocket
    room.usernames[user_id] = username[:24]

    # Cancel lonely timer if we now have 2+ users
    if room.user_count() >= 2 and room.empty_timer_task:
        room.empty_timer_task.cancel()
        room.empty_timer_task = None

    # Notify others: user joined
    await _broadcast(room, {
        "type": "system",
        "event": "user_joined",
        "username": username,
        "user_count": room.user_count(),
        "user_id": user_id,
    }, exclude=user_id)

    # Send current user list to new joiner
    await websocket.send_text(json.dumps({
        "type": "system",
        "event": "room_info",
        "room_name": room.name,
        "user_count": room.user_count(),
        "users": {uid: uname for uid, uname in room.usernames.items() if uid != user_id},
    }))

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg_type = data.get("type")

            if msg_type == "message":
                await _handle_message(room, user_id, data)

            elif msg_type == "ack":
                await _handle_ack(room, data.get("msg_id"))

    except WebSocketDisconnect:
        pass
    finally:
        _remove_user(room, user_id)
        await _broadcast(room, {
            "type": "system",
            "event": "user_left",
            "username": username,
            "user_count": room.user_count(),
            "user_id": user_id,
        })
        # If room empty, destroy it
        if room.user_count() == 0:
            _destroy_room(room_id)


# ── Message handling ───────────────────────────────────────────────────────────

async def _handle_message(room: Room, sender_id: str, data: dict):
    msg_id = str(uuid.uuid4())
    sent_at = time.time()

    envelope = {
        "type": "message",
        "msg_id": msg_id,
        "sender_id": sender_id,
        "sender_name": room.usernames.get(sender_id, "?"),
        "ciphertext": data.get("ciphertext", ""),   # opaque to server
        "iv": data.get("iv", ""),
        "sent_at": sent_at,
        "user_count": room.user_count(),
    }

    # Track undelivered
    undelivered = set(room.connections.keys()) - {sender_id}
    if undelivered:
        room.pending_messages.append({
            "msg_id": msg_id,
            "envelope": envelope,
            "undelivered": undelivered,
            "expire_at": None,   # set when all delivered
        })

    # Confirm to sender
    await room.connections[sender_id].send_text(json.dumps({
        "type": "sent_ack",
        "msg_id": msg_id,
        "sent_at": sent_at,
    }))

    # Relay to others
    for uid, ws in list(room.connections.items()):
        if uid == sender_id:
            continue
        try:
            await ws.send_text(json.dumps(envelope))
        except Exception:
            pass


async def _handle_ack(room: Room, msg_id: str):
    """Mark message as delivered; start 60-second expiry timer."""
    if not msg_id:
        return
    for pending in room.pending_messages:
        if pending["msg_id"] == msg_id:
            # (in a real multi-user case track per-user acks)
            pending["expire_at"] = time.time() + 60
            asyncio.create_task(_expire_message(room, msg_id))
            break


async def _expire_message(room: Room, msg_id: str):
    await asyncio.sleep(60)
    room.pending_messages = [
        m for m in room.pending_messages if m["msg_id"] != msg_id
    ]
    # Notify room that message self-destructed
    await _broadcast(room, {
        "type": "system",
        "event": "message_expired",
        "msg_id": msg_id,
    })


# ── Room lifecycle ─────────────────────────────────────────────────────────────

async def _lonely_room_timer(room_id: str):
    """Close room if no second user joins within 10 minutes."""
    # Warn at 9 minutes
    await asyncio.sleep(9 * 60)
    room = ROOMS.get(room_id)
    if not room or not room.active or room.user_count() >= 2:
        return

    await _broadcast(room, {
        "type": "system",
        "event": "warning",
        "message": "No one joined. Room closes in 60 seconds.",
    })

    await asyncio.sleep(60)
    room = ROOMS.get(room_id)
    if not room or not room.active or room.user_count() >= 2:
        return

    await _broadcast(room, {
        "type": "system",
        "event": "room_closing",
        "message": "Room closed: no second user joined within 10 minutes.",
    })
    _destroy_room(room_id)


def _destroy_room(room_id: str):
    room = ROOMS.pop(room_id, None)
    if room:
        room.active = False
        if room.empty_timer_task:
            room.empty_timer_task.cancel()
        room.connections.clear()
        room.pending_messages.clear()
        room.usernames.clear()


def _remove_user(room: Room, user_id: str):
    room.connections.pop(user_id, None)
    room.usernames.pop(user_id, None)


async def _broadcast(room: Room, payload: dict, exclude: str = None):
    dead = []
    for uid, ws in list(room.connections.items()):
        if uid == exclude:
            continue
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            dead.append(uid)
    for uid in dead:
        _remove_user(room, uid)


# ── Serve frontend ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
