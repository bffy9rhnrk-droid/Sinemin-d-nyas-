import os
import json
import sqlite3
import secrets
import hashlib
import hmac
from pathlib import Path
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field

APP_DIR = Path(__file__).resolve().parent
INDEX_FILE = APP_DIR / "index.html"
DB_PATH = os.getenv("DB_PATH", str(APP_DIR / "sinem.db"))
APP_PASSWORD = os.getenv("SINEM_PASSWORD", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")

app = FastAPI(title="Sinem'in Dünyası")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET or "development-only-change-this-secret",
    session_cookie="sinem_session",
    same_site="lax",
    https_only=os.getenv("RENDER", "") == "true",
    max_age=60 * 60 * 24 * 7,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)

def db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'player',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL DEFAULT '',
            photo_data TEXT NOT NULL DEFAULT '',
            owner TEXT NOT NULL DEFAULT 'sinem',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS stats (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS game_rooms (
            code TEXT PRIMARY KEY,
            game TEXT NOT NULL,
            state TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
        for key, value in [("cat_happiness", 75), ("cat_food", 65), ("points", 0)]:
            conn.execute("INSERT OR IGNORE INTO stats(key,value) VALUES(?,?)", (key, value))
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(items)").fetchall()]
        if "owner" not in cols:
            conn.execute("ALTER TABLE items ADD COLUMN owner TEXT NOT NULL DEFAULT 'sinem'")
        if "photo_data" not in cols:
            conn.execute("ALTER TABLE items ADD COLUMN photo_data TEXT NOT NULL DEFAULT ''")
        # Optional first-run bootstrap accounts. Passwords are only read from environment variables.
        now = datetime.now(timezone.utc).isoformat()
        bootstrap = [
            ("murat", os.getenv("MURAT_PASSWORD", ""), "Murat", "admin"),
            ("sinem", os.getenv("SINEM_PASSWORD", ""), "Sinem", "player"),
        ]
        for username, password, display_name, role in bootstrap:
            if password and not conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                salt = secrets.token_hex(16)
                password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 240000).hex()
                conn.execute("INSERT INTO users(username,password_hash,salt,display_name,role,created_at) VALUES(?,?,?,?,?,?)",
                             (username, password_hash, salt, display_name, role, now))
        count = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        if count == 0:
            now = datetime.now(timezone.utc).isoformat()
            conn.executemany(
                "INSERT INTO items(kind,title,body,owner,created_at) VALUES(?,?,?,?,?)",
                [
                    ("letter", "Sana küçük bir not 💌", "Bu köşe senin için hazırlandı. Buraya sana söylemek istediğim güzel şeyleri ekleyeceğim.", "sinem", now),
                    ("dream", "Birlikte yeni bir anı biriktirmek", "Beraber yapmak istediğimiz güzel bir şey.", "shared", now),
                ],
            )

init_db()

class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=200)

class ItemPayload(BaseModel):
    kind: str
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(default="", max_length=5000)
    photo_data: str = Field(default="", max_length=2500000)

class ActionPayload(BaseModel):
    action: str

def require_auth(request: Request):
    if request.session.get("authenticated") is not True or not request.session.get("username"):
        raise HTTPException(status_code=401, detail="Giriş yapmalısın.")

def current_user(request: Request):
    require_auth(request)
    return request.session["username"]

def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 240000).hex()

@app.get("/")
async def home():
    return FileResponse(INDEX_FILE)

@app.get("/api/session")
async def session_status(request: Request):
    if request.session.get("authenticated") is True and request.session.get("username"):
        return {"authenticated": True, "username": request.session["username"],
                "display_name": request.session.get("display_name", request.session["username"]),
                "role": request.session.get("role", "player")}
    return {"authenticated": False}

@app.post("/api/login")
async def login(payload: LoginPayload, request: Request):
    username = payload.username.strip().lower()
    with db() as conn:
        user = conn.execute("SELECT username,password_hash,salt,display_name,role FROM users WHERE username=?", (username,)).fetchone()
    # Fallback to environment-defined account creation if app's database existed before accounts were configured.
    if not user:
        env_password = os.getenv("MURAT_PASSWORD", "") if username == "murat" else os.getenv("SINEM_PASSWORD", "") if username == "sinem" else ""
        if env_password:
            salt = secrets.token_hex(16)
            now = datetime.now(timezone.utc).isoformat()
            password_hash = hash_password(env_password, salt)
            with db() as conn:
                conn.execute("INSERT OR IGNORE INTO users(username,password_hash,salt,display_name,role,created_at) VALUES(?,?,?,?,?,?)",
                             (username, password_hash, salt, "Murat" if username == "murat" else "Sinem", "admin" if username == "murat" else "player", now))
                user = conn.execute("SELECT username,password_hash,salt,display_name,role FROM users WHERE username=?", (username,)).fetchone()
    if not user or not hmac.compare_digest(hash_password(payload.password, user["salt"]), user["password_hash"]):
        raise HTTPException(status_code=401, detail="Kullanıcı adı veya şifre yanlış.")
    request.session.clear()
    request.session["authenticated"] = True
    request.session["username"] = user["username"]
    request.session["display_name"] = user["display_name"]
    request.session["role"] = user["role"]
    request.session["csrf"] = secrets.token_urlsafe(24)
    return {"ok": True, "username": user["username"], "display_name": user["display_name"], "role": user["role"]}

@app.post("/api/logout")
async def logout(request: Request):
    require_auth(request)
    request.session.clear()
    return {"ok": True}

@app.get("/api/state")
async def get_state(request: Request):
    require_auth(request)
    with db() as conn:
        username = current_user(request)
        items = [dict(r) for r in conn.execute(
            "SELECT id,kind,title,body,photo_data,created_at FROM items WHERE owner IN (?, 'shared') OR kind = 'memory' ORDER BY id DESC",
            (username,)
        ).fetchall()]
        username = current_user(request)
        stats = {r["key"]: r["value"] for r in conn.execute("SELECT key,value FROM stats WHERE key LIKE ?", (username + ":%",))}
        if not stats:
            stats = {"cat_happiness":75,"cat_food":65,"points":0}
    return {"items": items, "stats": stats}

@app.post("/api/items")
async def add_item(payload: ItemPayload, request: Request):
    require_auth(request)
    if payload.kind not in {"memory", "letter", "journal", "dream"}:
        raise HTTPException(status_code=400, detail="Geçersiz bölüm.")
    title = payload.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Başlık boş olamaz.")
    now = datetime.now(timezone.utc).isoformat()
    username = current_user(request)
    owner = "shared" if payload.kind in {"dream", "memory"} else username
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO items(kind,title,body,photo_data,owner,created_at) VALUES(?,?,?,?,?,?)",
            (payload.kind, title, payload.body.strip(), payload.photo_data, owner, now),
        )
        item_id = cur.lastrowid
        row = conn.execute("SELECT id,kind,title,body,photo_data,created_at FROM items WHERE id=?", (item_id,)).fetchone()
    return dict(row)

@app.delete("/api/items/{item_id}")
async def delete_item(item_id: int, request: Request):
    require_auth(request)
    username = current_user(request)
    with db() as conn:
        row = conn.execute("SELECT owner FROM items WHERE id=?", (item_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Kayıt bulunamadı.")
        item = conn.execute("SELECT kind FROM items WHERE id=?", (item_id,)).fetchone()
        if row["owner"] not in {username, "shared"} and not (item and item["kind"] == "memory"):
            raise HTTPException(status_code=403, detail="Bu kaydı silme iznin yok.")
        conn.execute("DELETE FROM items WHERE id=?", (item_id,))
    return {"ok": True}

@app.post("/api/action")
async def action(payload: ActionPayload, request: Request):
    require_auth(request)
    allowed = {"feed", "play", "quiz_correct"}
    if payload.action not in allowed:
        raise HTTPException(status_code=400, detail="Geçersiz işlem.")
    username = current_user(request)
    changes = {"feed": {"cat_food": 25, "cat_happiness": 8, "points": 2},
               "play": {"cat_happiness": 15, "cat_food": -5, "points": 3},
               "quiz_correct": {"points": 5}}
    with db() as conn:
        for short_key, delta in changes[payload.action].items():
            key = username + ":" + short_key
            current = conn.execute("SELECT value FROM stats WHERE key=?", (key,)).fetchone()
            new_value = (current["value"] if current else (75 if short_key=="cat_happiness" else 65 if short_key=="cat_food" else 0)) + delta
            if short_key.startswith("cat_"):
                new_value = max(0, min(100, new_value))
            conn.execute("INSERT INTO stats(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, new_value))
        stats = {r["key"].split(":",1)[1]: r["value"] for r in conn.execute("SELECT key,value FROM stats WHERE key LIKE ?", (username + ":%",))}
    return {"stats": stats}



class RoomCreatePayload(BaseModel):
    game: str = "tictactoe"

class RoomJoinPayload(BaseModel):
    code: str = Field(min_length=4, max_length=8)

class RoomActionPayload(BaseModel):
    code: str = Field(min_length=4, max_length=8)
    action: str
    value: str = ""

@app.post("/api/rooms")
async def create_room(payload: RoomCreatePayload, request: Request):
    require_auth(request)
    if payload.game not in {"tictactoe", "wouldyou"}:
        raise HTTPException(status_code=400, detail="Bu oyun türü desteklenmiyor.")
    code = secrets.token_hex(3).upper()
    now = datetime.now(timezone.utc).isoformat()
    if payload.game == "tictactoe":
        state = {
            "game": "tictactoe", "board": [""] * 9, "turn": "X",
            "players": {"X": "Oyuncu 1", "O": "Oyuncu 2"},
            "winner": "", "status": "waiting", "lastMove": ""
        }
    else:
        state = {
            "game": "wouldyou", "round": 0, "votes": {},
            "players": {"X": "Oyuncu 1", "O": "Oyuncu 2"},
            "status": "waiting", "lastPrompt": ""
        }
    with db() as conn:
        conn.execute(
            "INSERT INTO game_rooms(code,game,state,created_at) VALUES(?,?,?,?)",
            (code, payload.game, json.dumps(state), now)
        )
    return {"code": code, "game": payload.game, "state": state}

@app.post("/api/rooms/join")
async def join_room(payload: RoomJoinPayload, request: Request):
    require_auth(request)
    code = payload.code.strip().upper()
    with db() as conn:
        row = conn.execute("SELECT code,game,state FROM game_rooms WHERE code=?", (code,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Bu kodla oda bulunamadı.")
        state = json.loads(row["state"])
        if state.get("status") == "waiting":
            state["status"] = "playing"
            state["players"]["O"] = "Oyuncu 2"
            conn.execute("UPDATE game_rooms SET state=? WHERE code=?", (json.dumps(state), code))
    return {"code": code, "game": row["game"], "state": state}

@app.get("/api/rooms/{code}")
async def get_room(code: str, request: Request):
    require_auth(request)
    with db() as conn:
        row = conn.execute("SELECT code,game,state FROM game_rooms WHERE code=?", (code.upper(),)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Oda bulunamadı.")
    return {"code": row["code"], "game": row["game"], "state": json.loads(row["state"])}

@app.post("/api/rooms/action")
async def room_action(payload: RoomActionPayload, request: Request):
    require_auth(request)
    code = payload.code.strip().upper()
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT game,state FROM game_rooms WHERE code=?", (code,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Oda bulunamadı.")
        state = json.loads(row["state"])
        if row["game"] == "tictactoe":
            if payload.action == "move":
                try:
                    idx = int(payload.value)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Geçersiz hamle.")
                if state.get("status") != "playing" or state.get("winner") or idx < 0 or idx > 8:
                    raise HTTPException(status_code=400, detail="Bu hamle yapılamaz.")
                if state["board"][idx]:
                    raise HTTPException(status_code=400, detail="Bu kare dolu.")
                state["board"][idx] = state["turn"]
                state["lastMove"] = state["turn"]
                lines = [(0,1,2),(3,4,5),(6,7,8),(0,3,6),(1,4,7),(2,5,8),(0,4,8),(2,4,6)]
                if any(state["board"][a] and state["board"][a] == state["board"][b] == state["board"][c] for a,b,c in lines):
                    state["winner"] = state["turn"]
                elif all(state["board"]):
                    state["winner"] = "draw"
                else:
                    state["turn"] = "O" if state["turn"] == "X" else "X"
            elif payload.action == "reset":
                state.update({"board":[""]*9,"turn":"X","winner":"","status":"playing","lastMove":""})
            else:
                raise HTTPException(status_code=400, detail="Geçersiz oyun işlemi.")
        elif row["game"] == "wouldyou":
            prompts = [
                "Birlikte deniz kenarında gün batımı mı, yıldızların altında gece yürüyüşü mü?",
                "Birbirimize mektup yazmak mı, birlikte fotoğraf albümü hazırlamak mı?",
                "Evde battaniye altında film mi, spontane küçük bir gezi mi?",
                "Bir günlüğüne zamanda yolculuk: ilk buluşma mı, gelecekteki bir günümüz mü?",
                "Tatlı bir sürpriz mi, uzun uzun sohbet edeceğimiz bir akşam mı?"
            ]
            if payload.action == "vote":
                if payload.value not in {"A","B"}:
                    raise HTTPException(status_code=400, detail="Seçim geçersiz.")
                state.setdefault("votes", {})[payload.value] = state.get("votes", {}).get(payload.value, 0) + 1
                state["lastPrompt"] = prompts[state.get("round",0) % len(prompts)]
            elif payload.action == "next":
                state["round"] = (state.get("round",0) + 1) % len(prompts)
                state["votes"] = {}
                state["lastPrompt"] = prompts[state["round"]]
            else:
                raise HTTPException(status_code=400, detail="Geçersiz oyun işlemi.")
        conn.execute("UPDATE game_rooms SET state=? WHERE code=?", (json.dumps(state, ensure_ascii=False), code))
    return {"code": code, "game": row["game"], "state": state}

@app.get("/health")
async def health():
    return {"status": "ok"}
