#!/usr/bin/env python3
"""Portfolio Tracker - Server v3 (SQLite)"""

import json, threading, time, urllib.request, urllib.parse, socket, shutil
import sqlite3, hashlib, hmac as _hmac, secrets, os, math
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# ── .env loader ───────────────────────────────────────────────────────────────
def _load_env():
    env_file = Path(__file__).parent / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_env()

# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR  = Path(__file__).parent
PORT      = int(os.environ.get("PORT", 8080))
DB_PATH   = Path(os.environ.get("DB_PATH", str(BASE_DIR / "portfolio.db")))
BACKUP_DIR = BASE_DIR / "backups"
SESSION_TTL = 60 * 60 * 24 * 30  # 30 days

def _load_or_create_secret():
    f = BASE_DIR / ".jwt_secret"
    if f.exists(): return f.read_text().strip()
    s = secrets.token_hex(32)
    f.write_text(s); return s

JWT_SECRET = os.environ.get("JWT_SECRET") or _load_or_create_secret()

# ── Database ──────────────────────────────────────────────────────────────────
# ── Rate Limiter ──────────────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self):
        self._data = {}
        self._lock = threading.Lock()
    def is_allowed(self, ip, max_attempts, window_sec):
        now = time.time()
        with self._lock:
            attempts = [(t,c) for t,c in self._data.get(ip,[]) if now-t < window_sec]
            if sum(c for _,c in attempts) >= max_attempts:
                self._data[ip] = attempts; return False
            attempts.append((now,1)); self._data[ip] = attempts; return True
    def cleanup(self):
        now = time.time()
        with self._lock:
            self._data = {ip:[(t,c) for t,c in a if now-t<3600] for ip,a in self._data.items()}

_login_limiter = RateLimiter()
_api_limiter   = RateLimiter()
_PRICE_CACHE_TTL  = 15 * 60
_REFRESH_COOLDOWN = 10 * 60
_last_user_refresh: dict = {}
_refresh_lock2 = threading.Lock()
_refresh_running = False
_refresh_lock3 = threading.Lock()
_asset_cache: dict = {}

def _is_cache_fresh(symbol, ttl=None):
    t = ttl or _PRICE_CACHE_TTL
    row = db_one(f"SELECT 1 FROM prices_cache WHERE symbol=? AND price IS NOT NULL AND updated_at > datetime('now','-{t} seconds')", (symbol,))
    return row is not None

def _can_user_refresh(user_id):
    with _refresh_lock2:
        last = _last_user_refresh.get(user_id, 0)
        if time.time() - last < _REFRESH_COOLDOWN: return False
        _last_user_refresh[user_id] = time.time(); return True

def _seconds_until_refresh(user_id):
    with _refresh_lock2:
        return max(0, int(_REFRESH_COOLDOWN - (time.time() - _last_user_refresh.get(user_id,0))))

_db_local = threading.local()

def get_db() -> sqlite3.Connection:
    """Return a thread-local database connection."""
    if not hasattr(_db_local, "conn") or _db_local.conn is None:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _db_local.conn = conn
    return _db_local.conn

def db_exec(sql, params=()):
    conn = get_db()
    cur = conn.execute(sql, params)
    conn.commit()
    return cur

def db_one(sql, params=()):
    return get_db().execute(sql, params).fetchone()

def db_all(sql, params=()):
    return get_db().execute(sql, params).fetchall()

def init_db():
    """Create all tables if they don't exist."""
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id          TEXT PRIMARY KEY,
        username    TEXT UNIQUE NOT NULL COLLATE NOCASE,
        password    TEXT NOT NULL,
        role        TEXT NOT NULL DEFAULT 'user',
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        settings    TEXT NOT NULL DEFAULT '{}'
    );

    CREATE TABLE IF NOT EXISTS tickers (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        symbol       TEXT NOT NULL,
        name         TEXT NOT NULL DEFAULT '',
        yahoo_symbol TEXT NOT NULL DEFAULT '',
        type         TEXT NOT NULL DEFAULT 'stock',
        position     INTEGER NOT NULL DEFAULT 0,
        created_at   TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(user_id, symbol)
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ticker_id  INTEGER NOT NULL REFERENCES tickers(id) ON DELETE CASCADE,
        user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type       TEXT NOT NULL CHECK(type IN ('buy','sell')),
        date       TEXT NOT NULL,
        shares     REAL NOT NULL CHECK(shares > 0),
        price      REAL NOT NULL CHECK(price > 0),
        fee        REAL NOT NULL DEFAULT 0,
        currency   TEXT NOT NULL DEFAULT 'EUR',
        notes      TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS portfolio_targets (
        user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ticker_id INTEGER NOT NULL REFERENCES tickers(id) ON DELETE CASCADE,
        target_pct REAL NOT NULL DEFAULT 0,
        PRIMARY KEY(user_id, ticker_id)
    );

    CREATE TABLE IF NOT EXISTS price_targets (
        user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ticker_id INTEGER NOT NULL REFERENCES tickers(id) ON DELETE CASCADE,
        price_eur REAL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY(user_id, ticker_id)
    );

    CREATE TABLE IF NOT EXISTS price_history (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        timestamp TEXT NOT NULL,
        value_eur REAL NOT NULL,
        UNIQUE(user_id, timestamp)
    );

    CREATE TABLE IF NOT EXISTS prices_cache (
        symbol     TEXT PRIMARY KEY,
        price      REAL,
        prev_close REAL,
        day_pct    REAL,
        currency   TEXT DEFAULT 'EUR',
        raw_price  REAL,
        raw_currency TEXT DEFAULT 'USD',
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS market_list (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        symbol       TEXT NOT NULL,
        name         TEXT NOT NULL DEFAULT '',
        yahoo_symbol TEXT NOT NULL DEFAULT '',
        type         TEXT NOT NULL DEFAULT 'stock',
        UNIQUE(user_id, symbol)
    );

    CREATE TABLE IF NOT EXISTS day_start (
        user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        date       TEXT NOT NULL,
        prices_json TEXT NOT NULL DEFAULT '{}'
    );

    CREATE INDEX IF NOT EXISTS idx_tx_user    ON transactions(user_id);
    CREATE INDEX IF NOT EXISTS idx_tx_ticker  ON transactions(ticker_id);
    CREATE INDEX IF NOT EXISTS idx_hist_user  ON price_history(user_id, timestamp);
    CREATE INDEX IF NOT EXISTS idx_tickers_user ON tickers(user_id);
    """)
    conn.commit()
    print("  [db] schema OK")

# ── Auth helpers ──────────────────────────────────────────────────────────────
def hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260_000)
    return f"{salt}${dk.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        salt, dk_hex = stored.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260_000)
        return _hmac.compare_digest(dk.hex(), dk_hex)
    except: return False

def make_token(user_id: str) -> str:
    import base64
    payload = {"sub": user_id, "iat": int(time.time()), "exp": int(time.time()) + SESSION_TTL}
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    body   = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig    = _hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

def verify_token(token: str):
    try:
        import base64
        parts = token.split(".")
        if len(parts) != 3: return None
        h, b, s = parts
        expected = _hmac.new(JWT_SECRET.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest()
        if not _hmac.compare_digest(expected, base64.urlsafe_b64decode(s + "==")): return None
        payload = json.loads(base64.urlsafe_b64decode(b + "=="))
        if payload.get("exp", 0) < time.time(): return None
        return payload.get("sub")
    except: return None

# ── Data access layer ─────────────────────────────────────────────────────────
def get_user(user_id: str):
    return db_one("SELECT * FROM users WHERE id=?", (user_id,))

def get_user_by_username(username: str):
    return db_one("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,))

def load_data(user_id: str) -> dict:
    """Load full portfolio data for a user as a dict (legacy-compatible format)."""
    # Tickers
    tickers_rows = db_all(
        "SELECT id, symbol, name, yahoo_symbol, type FROM tickers WHERE user_id=? ORDER BY position, id",
        (user_id,)
    )
    # Map real SQLite id -> sequential id (1,2,3...) for frontend compatibility
    real_to_seq = {r["id"]: (i+1) for i, r in enumerate(tickers_rows)}
    tickers = [{"id": real_to_seq[r["id"]], "symbol": r["symbol"], "name": r["name"],
                "yahooSymbol": r["yahoo_symbol"], "type": r["type"]} for r in tickers_rows]

    ticker_ids = [r["id"] for r in tickers_rows]  # real SQLite ids

    # Transactions - use sequential ids as keys
    txns = {}
    if ticker_ids:
        placeholders = ",".join("?" * len(ticker_ids))
        tx_rows = db_all(
            f"SELECT ticker_id, type, date, shares, price, fee, currency, notes FROM transactions "
            f"WHERE user_id=? AND ticker_id IN ({placeholders}) ORDER BY date",
            (user_id, *ticker_ids)
        )
        for r in tx_rows:
            seq_id = str(real_to_seq.get(r["ticker_id"], r["ticker_id"]))
            if seq_id not in txns: txns[seq_id] = []
            tx = {"type": r["type"], "date": r["date"],
                  "shares": r["shares"], "price": r["price"]}
            if r["fee"]: tx["fee"] = r["fee"]
            if r["notes"]: tx["notes"] = r["notes"]
            txns[seq_id].append(tx)

    # Targets
    targets = {}
    if ticker_ids:
        tgt_rows = db_all(
            f"SELECT ticker_id, target_pct FROM portfolio_targets WHERE user_id=?",
            (user_id,)
        )
        for r in tgt_rows:
            seq_id = real_to_seq.get(r["ticker_id"])
            if seq_id: targets[seq_id] = r["target_pct"]

    # Price targets
    price_tgts = {}
    ptgt_rows = db_all("SELECT ticker_id, price_eur FROM price_targets WHERE user_id=?", (user_id,))
    for r in ptgt_rows:
        seq_id = real_to_seq.get(r["ticker_id"])
        if r["price_eur"] and seq_id: price_tgts[str(seq_id)] = r["price_eur"]

    # History
    hist_rows = db_all(
        "SELECT timestamp, value_eur FROM price_history WHERE user_id=? ORDER BY timestamp",
        (user_id,)
    )
    history = [{"t": r["timestamp"], "v": r["value_eur"]} for r in hist_rows]

    # Day start
    ds_row = db_one("SELECT date, prices_json FROM day_start WHERE user_id=?", (user_id,))
    day_start = {}
    if ds_row:
        try: day_start = {"date": ds_row["date"], "prices": json.loads(ds_row["prices_json"])}
        except: pass

    # Market list
    ml_rows = db_all(
        "SELECT symbol, name, yahoo_symbol, type FROM market_list WHERE user_id=? ORDER BY id",
        (user_id,)
    )
    market_list = [{"symbol": r["symbol"], "name": r["name"],
                    "yahooSymbol": r["yahoo_symbol"], "type": r["type"]} for r in ml_rows]

    # Settings
    user = get_user(user_id)
    settings = {}
    if user:
        try: settings = json.loads(user["settings"] or "{}")
        except: pass

    # Prices from cache
    prices = {}
    if tickers:
        for t in tickers:
            sym = t.get("yahooSymbol") or t["symbol"]
            row = db_one("SELECT price FROM prices_cache WHERE symbol=?", (sym,))
            if row and row["price"]: prices[str(t["id"])] = row["price"]

    # Day change pcts from cache
    day_change_pcts = {}
    for t in tickers:
        sym = t.get("yahooSymbol") or t["symbol"]
        row = db_one("SELECT day_pct FROM prices_cache WHERE symbol=?", (sym,))
        if row and row["day_pct"] is not None:
            day_change_pcts[t["id"]] = row["day_pct"]

    return {
        "tickers": tickers,
        "txns": txns,
        "targets": targets,
        "priceTgts": price_tgts,
        "history": history,
        "dayStart": day_start,
        "marketList": market_list,
        "settings": settings,
        "prices": prices,
        "dayChangePcts": day_change_pcts,
    }

def save_data(data: dict, user_id: str):
    """Save full portfolio data from legacy dict format."""
    conn = get_db()

    # Tickers
    existing = {r["symbol"]: r["id"] for r in db_all(
        "SELECT id, symbol FROM tickers WHERE user_id=?", (user_id,)
    )}
    for i, t in enumerate(data.get("tickers", [])):
        sym = t["symbol"]
        yahoo = t.get("yahooSymbol") or sym
        if sym in existing:
            conn.execute(
                "UPDATE tickers SET name=?, yahoo_symbol=?, type=?, position=? WHERE id=?",
                (t.get("name", sym), yahoo, t.get("type", "stock"), i, existing[sym])
            )
        else:
            conn.execute(
                "INSERT INTO tickers(user_id,symbol,name,yahoo_symbol,type,position) VALUES(?,?,?,?,?,?)",
                (user_id, sym, t.get("name", sym), yahoo, t.get("type", "stock"), i)
            )
    conn.commit()

    # Refresh ticker id map
    ticker_map = {r["symbol"]: r["id"] for r in db_all(
        "SELECT id, symbol FROM tickers WHERE user_id=?", (user_id,)
    )}

    # Transactions — full replace per ticker
    # Build sequential_id -> symbol map from submitted tickers
    seq_to_sym = {t.get("id"): t["symbol"] for t in data.get("tickers", []) if t.get("id") and t.get("symbol")}
    txns = data.get("txns", {})
    for tid_str, tx_list in txns.items():
        tid_int = int(tid_str) if str(tid_str).isdigit() else None
        if tid_int is None: continue
        # Find symbol by sequential id
        ticker_sym = seq_to_sym.get(tid_int)
        if not ticker_sym: continue
        real_tid = ticker_map.get(ticker_sym)
        if not real_tid: continue
        conn.execute("DELETE FROM transactions WHERE ticker_id=? AND user_id=?", (real_tid, user_id))
        for tx in tx_list:
            conn.execute(
                "INSERT INTO transactions(ticker_id,user_id,type,date,shares,price,fee,notes) VALUES(?,?,?,?,?,?,?,?)",
                (real_tid, user_id, tx["type"], tx.get("date",""), tx["shares"], tx["price"],
                 tx.get("fee", 0), tx.get("notes", ""))
            )
    conn.commit()

    # Targets
    for seq_tid, pct in data.get("targets", {}).items():
        seq_int = int(seq_tid) if str(seq_tid).isdigit() else None
        if seq_int is None: continue
        ticker_sym = seq_to_sym.get(seq_int)
        if not ticker_sym: continue
        real_tid = ticker_map.get(ticker_sym)
        if not real_tid: continue
        conn.execute(
            "INSERT OR REPLACE INTO portfolio_targets(user_id,ticker_id,target_pct) VALUES(?,?,?)",
            (user_id, real_tid, float(pct or 0))
        )
    conn.commit()

    # Price targets
    for seq_tid_str, price in data.get("priceTgts", {}).items():
        seq_int = int(seq_tid_str) if str(seq_tid_str).isdigit() else None
        if seq_int is None: continue
        ticker_sym = seq_to_sym.get(seq_int)
        if not ticker_sym: continue
        new_tid = ticker_map.get(ticker_sym)
        if not new_tid: continue
        conn.execute(
            "INSERT OR REPLACE INTO price_targets(user_id,ticker_id,price_eur) VALUES(?,?,?)",
            (user_id, new_tid, float(price) if price else None)
        )
    conn.commit()

    # History — upsert
    for h in data.get("history", []):
        if h.get("t") and h.get("v") is not None:
            conn.execute(
                "INSERT OR REPLACE INTO price_history(user_id,timestamp,value_eur) VALUES(?,?,?)",
                (user_id, h["t"], h["v"])
            )
    conn.commit()

    # Day start
    ds = data.get("dayStart", {})
    if ds.get("date"):
        conn.execute(
            "INSERT OR REPLACE INTO day_start(user_id,date,prices_json) VALUES(?,?,?)",
            (user_id, ds["date"], json.dumps(ds.get("prices", {})))
        )
        conn.commit()

    # Market list
    if "marketList" in data:
        conn.execute("DELETE FROM market_list WHERE user_id=?", (user_id,))
        for m in data["marketList"]:
            conn.execute(
                "INSERT OR IGNORE INTO market_list(user_id,symbol,name,yahoo_symbol,type) VALUES(?,?,?,?,?)",
                (user_id, m["symbol"], m.get("name",""), m.get("yahooSymbol",m["symbol"]), m.get("type","stock"))
            )
        conn.commit()

    # Settings
    if "settings" in data:
        conn.execute("UPDATE users SET settings=? WHERE id=?",
                     (json.dumps(data["settings"]), user_id))
        conn.commit()

# ── Migration from JSON ───────────────────────────────────────────────────────
def migrate_from_json():
    """Migrate legacy JSON files to SQLite on first run."""
    users_json = BASE_DIR / "users.json"
    data_dir   = BASE_DIR / "data"

    users_in_db = db_all("SELECT id FROM users")
    if users_in_db:
        return  # already migrated

    migrated = 0

    # Case 1: new multi-user setup with users.json
    if users_json.exists():
        try:
            users = json.loads(users_json.read_text("utf-8"))
            for uid, u in users.items():
                db_exec(
                    "INSERT OR IGNORE INTO users(id,username,password,role) VALUES(?,?,?,?)",
                    (uid, u["username"], u["password"], u.get("role","user"))
                )
                # Load portfolio data
                data_file = data_dir / uid / "portfolio_data.json"
                if data_file.exists():
                    try:
                        data = json.loads(data_file.read_text("utf-8"))
                        save_data(data, uid)
                        migrated += 1
                        print(f"  [migrate] {u['username']} → SQLite ({len(data.get('tickers',[]))} tickers)")
                    except Exception as e:
                        print(f"  [migrate] {uid}: {e}")
        except Exception as e:
            print(f"  [migrate] users.json: {e}")

    # Case 2: legacy single-file setup
    elif (BASE_DIR / "portfolio_data.json").exists():
        uid = "default"
        pw  = hash_password("admin")
        db_exec("INSERT OR IGNORE INTO users(id,username,password,role) VALUES(?,?,?,?)",
                (uid, "admin", pw, "admin"))
        try:
            data = json.loads((BASE_DIR / "portfolio_data.json").read_text("utf-8"))
            save_data(data, uid)
            migrated += 1
            print(f"  [migrate] legacy portfolio_data.json → SQLite")
            print(f"  [migrate] Login: admin / admin  ← CHANGE PASSWORD!")
        except Exception as e:
            print(f"  [migrate] portfolio_data.json: {e}")

    else:
        print("  [db] fresh install, no migration needed")

    if migrated:
        print(f"  [migrate] done — {migrated} user(s) migrated to {DB_PATH}")

# ── Yahoo Finance ─────────────────────────────────────────────────────────────
YAHOO_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json",
}

def fetch_yahoo(symbol):
    url = f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(symbol)}?interval=1d&range=1d"
    try:
        req = urllib.request.Request(url, headers=YAHOO_HEADERS)
        with urllib.request.urlopen(req, timeout=6) as r:
            d = json.loads(r.read().decode())
        meta = d["chart"]["result"][0]["meta"]
        price = meta.get("regularMarketPrice")
        prev  = meta.get("previousClose") or meta.get("chartPreviousClose")
        cur   = meta.get("currency","USD").upper()
        if not price or price <= 0: return {"error":"no price"}
        chg = meta.get("regularMarketChangePercent")
        return {"price":price, "prev":prev, "currency":cur,
                "dayChangePct": round(chg,2) if chg else None}
    except Exception as e:
        return {"error": str(e)[:60]}

def get_eurusd():
    r = fetch_yahoo("EURUSD=X")
    return r["price"] if "price" in r else 0.925

def get_gbpeur():
    r = fetch_yahoo("GBPEUR=X")
    return r["price"] if "price" in r else 1.15

def to_eur(price, currency, eurusd):
    if price is None: return None
    c = currency.upper() if currency else "USD"
    if c == "EUR": return price
    if c in ("GBP",): return price * 1.175
    if c in ("GBp","GBX","PENCE"): return (price/100) * 1.175
    return price / eurusd

YAHOO_MAP = {
    "EQQQ":"EQQQ.DE","CSPX":"CSPX.AS","WDEF":"WDEF.MI",
    "GOOGL":"ABEA.DE","AMZN":"AMZ.DE","MSFT":"MSF.DE",
    "NVDA":"NVD.DE","UBER":"UT8.DE","AVGO":"1YD.DE",
    "NFLX":"NFC.DE","V":"3V64.DE","AMD":"AMD.DE",
    "SSLN":"SSLN.MI","ENS":"ENS-USD","BP":"BPE5.DE",
    "RR":"RRU.DE","TSLA":"TL0.DE","AAPL":"APC.DE",
    "META":"FB2A.DE","DBK":"DBK.DE","CBK":"CBK.DE",
    "ETH":"ETH-EUR","BTC":"BTC-EUR","XRP":"XRP-EUR","SOL":"SOL-EUR",
}

MARKET_TICKERS = [
    ("BTC",    "BTC-USD",  "Bitcoin"),
    ("GOLD",   "GC=F",     "Gold"),
    ("USDUAH", "USDUAH=X", "USD/UAH"),
    ("EURUAH", "EURUAH=X", "EUR/UAH"),
    ("EURUSD", "EURUSD=X", "EUR/USD"),
    ("GBPEUR", "GBPEUR=X", "GBP/EUR"),
    ("SP500",  "^GSPC",    "S&P 500"),
    ("NASDAQ", "^IXIC",    "NASDAQ"),
    ("DOW",    "^DJI",     "Dow Jones"),
    ("RUT",    "^RUT",     "Russell 2000"),
]

_market_cache = {"data": {}, "ts": 0}
_market_lock  = threading.Lock()

def fetch_market():
    with _market_lock:
        if _market_cache["data"] and (time.time() - _market_cache["ts"]) < 60:
            return _market_cache["data"]
    eurusd = get_eurusd()
    result = {}
    lock2  = threading.Lock()

    def fetch_one(item):
        key, sym, label = item
        r = fetch_yahoo(sym)
        if "error" in r: return
        price = r["price"]; prev = r.get("prev") or price; cur = r["currency"]
        is_rate = key in ("USDUAH","EURUAH","EURUSD","GBPEUR")
        dp  = price if is_rate else to_eur(price, cur, eurusd)
        dpr = prev  if is_rate else to_eur(prev,  cur, eurusd)
        chg = ((dp-dpr)/dpr*100) if dpr else 0
        with lock2:
            result[key] = {"label":label,"price":round(dp,4),"change_pct":round(chg,2),"is_rate":is_rate}

    threads = [threading.Thread(target=fetch_one, args=(item,)) for item in MARKET_TICKERS]
    for t in threads: t.start()
    for t in threads: t.join()
    with _market_lock:
        _market_cache.update({"data": result, "ts": time.time()})
    return result

def update_prices_cache(symbol, price, prev_close, day_pct, currency="EUR",
                         raw_price=None, raw_currency="USD"):
    """Update prices_cache table."""
    db_exec(
        """INSERT OR REPLACE INTO prices_cache
           (symbol,price,prev_close,day_pct,currency,raw_price,raw_currency,updated_at)
           VALUES(?,?,?,?,?,?,?,datetime('now'))""",
        (symbol, price, prev_close, day_pct, currency, raw_price, raw_currency)
    )

# ── Portfolio calculations ────────────────────────────────────────────────────
def calc_portfolio_value_db(user_id: str) -> float:
    """Calculate total portfolio value from DB prices_cache."""
    tickers = db_all("SELECT id, symbol, yahoo_symbol FROM tickers WHERE user_id=?", (user_id,))
    total = 0.0
    for t in tickers:
        sym = t["yahoo_symbol"] or t["symbol"]
        price_row = db_one("SELECT price FROM prices_cache WHERE symbol=?", (sym,))
        if not price_row or not price_row["price"]: continue
        price = price_row["price"]
        # Calculate shares
        tx_rows = db_all(
            "SELECT type, shares, price FROM transactions WHERE ticker_id=? ORDER BY date",
            (t["id"],)
        )
        shares = 0.0; cost = 0.0
        for tx in tx_rows:
            if tx["type"] == "buy":
                cost += tx["shares"] * tx["price"]; shares += tx["shares"]
            elif shares > 0:
                avg = cost / shares; s = min(tx["shares"], shares)
                cost -= s * avg; shares -= s
        total += max(0.0, shares) * price
    return round(total, 2)

def do_snapshot(user_id: str):
    """Take a portfolio snapshot and save to price_history."""
    from datetime import date as _date
    if _date.today().weekday() >= 5: return
    now_dt = datetime.now()
    if now_dt.hour < 7 or now_dt.hour >= 18: return

    # Check enough prices loaded
    tickers = db_all("SELECT id, yahoo_symbol, symbol FROM tickers WHERE user_id=?", (user_id,))
    if not tickers: return
    loaded = sum(1 for t in tickers if db_one(
        "SELECT 1 FROM prices_cache WHERE symbol=? AND price IS NOT NULL",
        (t["yahoo_symbol"] or t["symbol"],)
    ))
    if loaded < max(1, len(tickers) * 0.7):
        return

    v = calc_portfolio_value_db(user_id)
    if v <= 0: return

    # Sanity check
    last = db_one(
        "SELECT value_eur FROM price_history WHERE user_id=? ORDER BY timestamp DESC LIMIT 1",
        (user_id,)
    )
    if last and last["value_eur"] > 0 and v < last["value_eur"] * 0.5:
        print(f"  [snapshot] skip suspicious drop {last['value_eur']}→{v}")
        return

    now_str = now_dt.isoformat(timespec="minutes")
    bucket  = now_str[:15]  # 10-min buckets

    existing = db_one(
        "SELECT timestamp FROM price_history WHERE user_id=? AND timestamp LIKE ?",
        (user_id, bucket + "%")
    )
    if existing:
        db_exec("UPDATE price_history SET value_eur=?, timestamp=? WHERE user_id=? AND timestamp LIKE ?",
                (v, now_str, user_id, bucket + "%"))
    else:
        db_exec("INSERT OR REPLACE INTO price_history(user_id,timestamp,value_eur) VALUES(?,?,?)",
                (user_id, now_str, v))

    print(f"  [snapshot] {user_id} {now_str} → €{v}")

def do_day_start(user_id: str, force=False):
    """Record prices at day start for daily P&L calculation."""
    if datetime.now().weekday() >= 5: return
    today = datetime.now().strftime("%Y-%m-%d")
    ds = db_one("SELECT date FROM day_start WHERE user_id=?", (user_id,))
    if ds and ds["date"] == today and not force: return

    tickers = db_all("SELECT id, yahoo_symbol, symbol FROM tickers WHERE user_id=?", (user_id,))
    prices = {}
    for t in tickers:
        sym = t["yahoo_symbol"] or t["symbol"]
        row = db_one("SELECT price FROM prices_cache WHERE symbol=?", (sym,))
        if row and row["price"]: prices[str(t["id"])] = row["price"]
    if not prices: return

    db_exec("INSERT OR REPLACE INTO day_start(user_id,date,prices_json) VALUES(?,?,?)",
            (user_id, today, json.dumps(prices)))
    print(f"  [day start] {user_id} {today}")

# ── Backup ────────────────────────────────────────────────────────────────────
def make_backup(reason="manual", user_id=None):
    """Export user data as JSON backup."""
    if not user_id: return
    backup_dir = BACKUP_DIR / user_id
    backup_dir.mkdir(parents=True, exist_ok=True)
    ts  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dst = backup_dir / f"portfolio_{ts}_{reason}.json"
    data = load_data(user_id)
    dst.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
    # Keep only 30 most recent
    old_backups = sorted(backup_dir.glob("portfolio_*.json"))[:-30]
    for f in old_backups: f.unlink()
    print(f"  [backup] {user_id}/{dst.name}")
    return dst

# ── Background thread ─────────────────────────────────────────────────────────
_last_snap_min = -1
_last_day = ""

def refresh_prices(user_id: str):
    """Fetch prices for all user tickers and update cache + snapshot."""
    tickers = db_all("SELECT id, symbol, yahoo_symbol FROM tickers WHERE user_id=?", (user_id,))
    if not tickers: return
    eurusd = get_eurusd()
    lock   = threading.Lock()
    errors = [0]

    def fetch_one(t):
        sym = t["yahoo_symbol"] or t["symbol"]
        r   = fetch_yahoo(sym)
        if "error" in r:
            with lock: errors[0] += 1
            return
        cur   = r["currency"]
        price = round(to_eur(r["price"], cur, eurusd), 4)
        prev  = round(to_eur(r["prev"],  cur, eurusd), 4) if r.get("prev") else None
        day_p = r.get("dayChangePct")
        if day_p is None and prev and prev > 0:
            day_p = round((price - prev) / prev * 100, 2)
        with lock:
            update_prices_cache(sym, price, prev, day_p, "EUR", r["price"], cur)

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=15) as ex:
        list(ex.map(fetch_one, tickers))

    do_snapshot(user_id)
    print(f"  [prices] {user_id}: {len(tickers)-errors[0]}/{len(tickers)} OK")

def bg():
    global _last_snap_min, _last_day
    while True:
        time.sleep(60)
        now = datetime.now()
        snap_min = (now.hour * 60 + now.minute) // 5
        if snap_min != _last_snap_min:
            _last_snap_min = snap_min
            for uid in [r["id"] for r in db_all("SELECT id FROM users")]:
                try: refresh_prices(uid)
                except Exception as e: print(f"  [price err] {uid}: {e}")

        d = now.strftime("%Y-%m-%d")
        if d != _last_day:
            _last_day = d
            for uid in [r["id"] for r in db_all("SELECT id FROM users")]:
                try: do_day_start(uid)
                except: pass
                try: make_backup("daily", uid)
                except: pass
            threading.Thread(target=_update_all_targets_all_users, daemon=True).start()

def _update_all_targets_all_users():
    for uid in [r["id"] for r in db_all("SELECT id FROM users")]:
        try: update_analyst_targets(uid)
        except Exception as e: print(f"  [targets err] {uid}: {e}")

def update_analyst_targets(user_id: str):
    """Fetch analyst target prices via yfinance and store in DB."""
    try:
        import yfinance as _yf, math as _math
    except ImportError:
        print("  [targets] yfinance not installed"); return

    tickers = db_all("SELECT id, symbol, yahoo_symbol FROM tickers WHERE user_id=?", (user_id,))
    if not tickers: return
    eurusd = get_eurusd()
    EU_TO_US = {
        "APC":"AAPL","NVD":"NVDA","AMZ":"AMZN","MSF":"MSFT","ABEA":"GOOGL",
        "6RV":"APP","UT8":"UBER","3UX":"CLSK","1YD":"AVGO","NFC":"NFLX",
        "3V64":"V","6B0":"SOFI","7KY":"HOOD","BPE5":"BP.L","A00":"RGTI",
        "TL0":"TSLA","FB2A":"META","RRU":"RR.L","ASME":"ASML",
    }
    eu_sfx = (".DE",".DU",".MU",".F",".SG",".AS",".MI")
    changed = 0
    for t in tickers:
        ysym = t["yahoo_symbol"] or t["symbol"]
        base = ysym.split(".")[0].upper()
        us = EU_TO_US.get(base) or (ysym if not any(ysym.upper().endswith(s) for s in eu_sfx) else None)
        if not us: continue
        try:
            info = _yf.Ticker(us).info or {}
            tp = info.get("targetMeanPrice")
            if tp and not _math.isnan(float(tp)):
                price_eur = round(float(tp) / 100 * 1.175, 2) if us.endswith(".L") else round(float(tp) / eurusd, 2)
                db_exec(
                    "INSERT OR REPLACE INTO price_targets(user_id,ticker_id,price_eur,updated_at) VALUES(?,?,?,datetime('now'))",
                    (user_id, t["id"], price_eur)
                )
                changed += 1
        except: pass
    if changed:
        print(f"  [targets] {user_id}: updated {changed} analyst targets")

def seed_history_from_yahoo(user_id: str):
    """Build 3-month portfolio history and store in price_history table."""
    tickers = db_all("SELECT id, symbol, yahoo_symbol, type FROM tickers WHERE user_id=?", (user_id,))
    if not tickers: return {"error": "no tickers"}

    eurusd = get_eurusd()
    CRYPTO = ("-USD","-EUR","-BTC","-ETH")
    positions = []
    for t in tickers:
        ysym = t["yahoo_symbol"] or t["symbol"]
        if any(ysym.upper().endswith(s) for s in CRYPTO): continue
        tx_rows = db_all("SELECT type,shares,price FROM transactions WHERE ticker_id=? ORDER BY date", (t["id"],))
        shares = 0.0; cost = 0.0
        for tx in tx_rows:
            if tx["type"] == "buy": cost += tx["shares"]*tx["price"]; shares += tx["shares"]
            elif shares > 0:
                avg = cost/shares; s = min(tx["shares"],shares); cost -= s*avg; shares -= s
        if max(0.0, shares) > 0:
            positions.append({"sym": ysym, "shares": max(0.0, shares)})

    if not positions: return {"error": "no positions"}

    from datetime import date as _date, timedelta as _td
    daily_val = {}; daily_count = {}

    for pos in positions:
        url = (f"https://query1.finance.yahoo.com/v8/finance/chart/"
               f"{urllib.parse.quote(pos['sym'])}?interval=1d&range=3mo")
        try:
            req = urllib.request.Request(url, headers=YAHOO_HEADERS)
            with urllib.request.urlopen(req, timeout=15) as r:
                j = json.loads(r.read().decode())
            res    = j["chart"]["result"][0]
            tss    = res.get("timestamp") or []
            closes = res["indicators"]["quote"][0]["close"]
            cur    = res["meta"].get("currency","USD").upper()
            for ts, c in zip(tss, closes):
                if c is None: continue
                d = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
                if _date.fromisoformat(d).weekday() >= 5: continue
                p = to_eur(c, cur, eurusd) or 0
                daily_val[d]   = daily_val.get(d, 0.0) + pos["shares"] * p
                daily_count[d] = daily_count.get(d, 0) + 1
        except Exception as e:
            print(f"  [seed] {pos['sym']}: {e}")

    if not daily_val: return {"error": "no data"}

    threshold = max(1, len(positions) * 0.5)
    good = {d: v for d, v in daily_val.items()
            if daily_count.get(d, 0) >= threshold and v > 0}
    if not good: good = dict(daily_val)

    import random; random.seed(42)
    sorted_days = sorted(good.items())
    history = []
    for i, (date_str, close_val) in enumerate(sorted_days):
        prev_close = sorted_days[i-1][1] if i > 0 else close_val
        hours = list(range(9, 18))
        n = len(hours)
        for j, hour in enumerate(hours):
            t_ratio = j / (n - 1)
            base = prev_close + (close_val - prev_close) * t_ratio
            noise = (random.random() - 0.5) * 0.003 * base
            history.append({"t": f"{date_str}T{hour:02d}:00", "v": round(base + noise, 2)})
        history[-1]["v"] = round(close_val, 2)

    # Save to DB
    conn = get_db()
    conn.execute("DELETE FROM price_history WHERE user_id=?", (user_id,))
    for h in history:
        conn.execute("INSERT OR REPLACE INTO price_history(user_id,timestamp,value_eur) VALUES(?,?,?)",
                     (user_id, h["t"], h["v"]))
    conn.commit()
    return {"history": history, "points": len(history)}


def resolve_yahoo_symbol(symbol):
    """Try symbol as-is first, then with exchange fallbacks for bare symbols."""
    if not symbol: return symbol
    # If symbol already has an exchange suffix or is a crypto pair, use as-is
    if any(symbol.endswith(s) for s in [".DE",".DU",".MU",".F",".SG",".AS",".MI","-EUR","-USD","-GBP"]):
        return symbol
    if "/" in symbol or "-" in symbol:
        return symbol
    # Known US symbols — use as-is
    if symbol.upper() in KNOWN_US_SYMBOLS:
        return symbol
    # Bare symbol — try with each exchange suffix
    for suffix in EXCHANGE_FALLBACKS:
        candidate = symbol + suffix
        url = f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(candidate)}?interval=1d&range=1d"
        try:
            req = urllib.request.Request(url, headers=YAHOO_HEADERS)
            with urllib.request.urlopen(req, timeout=6) as r:
                j = json.loads(r.read().decode())
            price = j["chart"]["result"][0]["meta"].get("regularMarketPrice")
            if price and price > 0:
                return candidate
        except:
            continue
    return symbol  # fallback to original


def fetch_premarket(eu_symbol, eurusd):
    """
    Fetch premarket/afterhours price for a symbol.
    Returns {"preMarket": price_eur, "preMarketPct": pct, "source": "us"|"etf"|None}
    """
    result = {"preMarket": None, "preMarketPct": None, "afterHours": None, "afterHoursPct": None}

    # Check if it's an ETF with proxy
    proxy_us = ETF_PROXY.get(eu_symbol)
    if proxy_us:
        try:
            # Fetch both proxy and EU close to compute ratio
            url_us = f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(proxy_us)}?interval=1d&range=5d"
            req = urllib.request.Request(url_us, headers=YAHOO_HEADERS)
            with urllib.request.urlopen(req, timeout=10) as r:
                d = json.loads(r.read().decode())
            meta = d["chart"]["result"][0]["meta"]
            us_close = meta.get("regularMarketPrice") or meta.get("previousClose")
            us_prev  = meta.get("previousClose") or meta.get("chartPreviousClose")
            pre = meta.get("preMarketPrice")
            post = meta.get("postMarketPrice")

            # Fetch EU close
            url_eu = f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(eu_symbol)}?interval=1d&range=5d"
            req_eu = urllib.request.Request(url_eu, headers=YAHOO_HEADERS)
            with urllib.request.urlopen(req_eu, timeout=10) as r2:
                d2 = json.loads(r2.read().decode())
            eu_close = d2["chart"]["result"][0]["meta"].get("regularMarketPrice") or d2["chart"]["result"][0]["meta"].get("previousClose")

            if eu_close and us_close and us_prev:
                # Apply % change from US to EU close
                if pre and pre > 0:
                    ratio = pre / us_prev
                    result["preMarket"] = round(eu_close * ratio, 2)
                    result["preMarketPct"] = round((ratio - 1) * 100, 2)
                if post and post > 0:
                    ratio_post = post / us_prev
                    result["afterHours"] = round(eu_close * ratio_post, 2)
                    result["afterHoursPct"] = round((ratio_post - 1) * 100, 2)
                result["source"] = "etf_proxy"
        except Exception as e:
            print(f"  [premarket] ETF proxy {eu_symbol}: {e}")
        return result

    # Check direct US equivalent
    us_sym = EU_PREMARKET_MAP.get(eu_symbol)

    # For direct US symbols (APP, CLSK etc)
    eu_suffixes = (".DE",".DU",".MU",".F",".SG",".AS",".MI",".L")
    if not us_sym and not any(eu_symbol.upper().endswith(s) for s in eu_suffixes):
        us_sym = eu_symbol  # already US symbol

    if not us_sym:
        return result

    try:
        url = f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(us_sym)}?interval=1d&range=5d"
        req = urllib.request.Request(url, headers=YAHOO_HEADERS)
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode())
        meta = d["chart"]["result"][0]["meta"]
        cur  = meta.get("currency","USD").upper()
        prev = meta.get("previousClose") or meta.get("chartPreviousClose") or meta.get("regularMarketPrice")
        pre  = meta.get("preMarketPrice")
        post = meta.get("postMarketPrice")
        pre_chg  = meta.get("preMarketChangePercent")
        post_chg = meta.get("postMarketChangePercent")

        def conv(p):
            if p is None: return None
            if cur == "EUR": return round(p, 2)
            if cur == "GBP": return round(p * get_gbpeur(), 2)
            if cur in ("GBp","GBX"): return round(p/100 * get_gbpeur(), 2)
            return round(p / eurusd, 2)

        if pre and pre > 0:
            result["preMarket"] = conv(pre)
            result["preMarketPct"] = round(pre_chg, 2) if pre_chg else (round((pre-prev)/prev*100,2) if prev else None)
        if post and post > 0:
            result["afterHours"] = conv(post)
            result["afterHoursPct"] = round(post_chg, 2) if post_chg else (round((post-prev)/prev*100,2) if prev else None)
        result["source"] = "us_direct"
    except Exception as e:
        print(f"  [premarket] {eu_symbol}({us_sym}): {e}")

    return result



def is_market_open(symbol=""):
    """Check if market is currently open based on symbol type and current UTC time."""
    from datetime import datetime as _dt, timezone as _tz, time as _time
    now_utc = _dt.now(_tz.utc)
    weekday = now_utc.weekday()  # 0=Mon, 6=Sun
    if weekday >= 5:  # weekend
        return {"eu_open": False, "us_open": False, "us_premarket": False, "us_afterhours": False}

    # EU (Xetra/Euronext): 08:00-16:30 UTC (9:00-17:30 CET)
    eu_open = _time(8,0) <= now_utc.time() <= _time(16,30)

    # US NYSE/NASDAQ: 13:30-20:00 UTC (9:30-16:00 ET)
    us_open = _time(13,30) <= now_utc.time() <= _time(20,0)

    # US Premarket: 08:00-13:30 UTC (4:00-9:30 ET)
    us_premarket = _time(8,0) <= now_utc.time() < _time(13,30)

    # US After-hours: 20:00-00:00 UTC (16:00-20:00 ET)
    us_afterhours = _time(20,0) <= now_utc.time() <= _time(23,59)

    return {
        "eu_open": eu_open,
        "us_open": us_open,
        "us_premarket": us_premarket,
        "us_afterhours": us_afterhours,
        "weekday": weekday,
    }



def get_gbpeur():
    r = fetch_yahoo("GBPEUR=X")
    return r["price"] if "price" in r else 1.15



# ── Market cache refresh ──────────────────────────────────────────────────────
def _refresh_market_cache(symbols: list, force_period: bool = False):
    global _refresh_running
    with _refresh_lock3:
        if _refresh_running and not force_period: return
        _refresh_running = True
    try:
        from datetime import date as _date, timedelta as _td, timezone as _tz
        eurusd = get_eurusd()
        update_prices_cache("EURUSD=X", eurusd, None, None)
        def fetch_one(sym):
            if not sym: return
            fresh = db_one("SELECT price,day_pct,m1_pct,ytd_pct,y1_pct FROM prices_cache WHERE symbol=? AND m1_pct IS NOT NULL AND updated_at > datetime('now','-3600 seconds')", (sym,))
            if fresh and _is_cache_fresh(sym) and not force_period: return
            if fresh and not force_period:
                r = fetch_yahoo(sym)
                if "error" not in r:
                    cur = r["currency"]; price_eur = round(to_eur(r["price"],cur,eurusd),2)
                    prev_eur = round(to_eur(r["prev"],cur,eurusd),2) if r.get("prev") else None
                    day_pct = r.get("dayChangePct")
                    if day_pct is None and prev_eur and prev_eur > 0:
                        day_pct = round((price_eur-prev_eur)/prev_eur*100,2)
                    update_prices_cache(sym,price_eur,prev_eur,day_pct,m1_pct=fresh["m1_pct"],ytd_pct=fresh["ytd_pct"],y1_pct=fresh["y1_pct"])
                return
            try:
                url = f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(sym)}?interval=1d&range=2y"
                req = urllib.request.Request(url, headers=_get_yahoo_headers())
                with urllib.request.urlopen(req, timeout=10) as r: j = json.loads(r.read().decode())
                res = j["chart"]["result"][0]; meta = res["meta"]
                cur = meta.get("currency","USD").upper(); raw = meta.get("regularMarketPrice")
                tss = res.get("timestamp") or []; cls = res["indicators"]["quote"][0]["close"]
                today = _date.today(); dc = {}
                for ts,c in zip(tss,cls):
                    if c: dc[datetime.fromtimestamp(ts,_tz.utc).strftime("%Y-%m-%d")] = c
                def cc(td):
                    for i in range(10):
                        d = (td-_td(days=i)).isoformat()
                        if d in dc: return dc[d]
                    return None
                def pct(a,b): return round((a-b)/b*100,2) if a and b else None
                m1 = pct(raw,cc(today-_td(days=30))); ytd = pct(raw,cc(_date(today.year-1,12,31))); y1 = pct(raw,cc(today-_td(days=365)))
                price_eur = round(to_eur(raw,cur,eurusd),2)
                prev_raw = meta.get("previousClose") or meta.get("chartPreviousClose")
                prev_eur = round(to_eur(prev_raw,cur,eurusd),2) if prev_raw else None
                dp_raw = meta.get("regularMarketChangePercent"); day_pct = round(dp_raw,2) if dp_raw else None
                if day_pct is None and prev_eur and prev_eur > 0: day_pct = round((price_eur-prev_eur)/prev_eur*100,2)
                update_prices_cache(sym,price_eur,prev_eur,day_pct,m1_pct=m1,ytd_pct=ytd,y1_pct=y1)
            except: pass
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=10) as ex: list(ex.map(fetch_one, symbols))
        print(f"  [market cache] refreshed {len(symbols)} symbols")
    finally:
        with _refresh_lock3: _refresh_running = False


def _update_period_pcts_for_symbols(symbols: list):
    from datetime import date as _date, timedelta as _td, timezone as _tz
    from concurrent.futures import ThreadPoolExecutor
    done = [0]
    def calc_pcts(raw, dc, today):
        def cc(td):
            for i in range(10):
                d = (td-_td(days=i)).isoformat()
                if d in dc: return dc[d]
            return None
        def pct(a,b): return round((a-b)/b*100,2) if a and b else None
        return pct(raw,cc(today-_td(days=30))), pct(raw,cc(_date(today.year-1,12,31))), pct(raw,cc(today-_td(days=365)))
    def fetch_one(sym):
        today = _date.today(); m1=ytd=y1=None
        for host in ("query1","query2"):
            try:
                url = f"https://{host}.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(sym)}?interval=1d&range=2y"
                req = urllib.request.Request(url, headers=_get_yahoo_headers())
                with urllib.request.urlopen(req, timeout=10) as r: j = json.loads(r.read().decode())
                res = j["chart"]["result"][0]; raw = res["meta"].get("regularMarketPrice")
                if not raw: continue
                tss = res.get("timestamp") or []; cls = res["indicators"]["quote"][0]["close"]
                dc = {}
                for ts,c in zip(tss,cls):
                    if c: dc[datetime.fromtimestamp(ts,_tz.utc).strftime("%Y-%m-%d")] = c
                if dc: m1,ytd,y1 = calc_pcts(raw,dc,today); break
            except: continue
        if m1 is None:
            try:
                import yfinance as _yf
                t = _yf.Ticker(sym); hist = t.history(period="2y",auto_adjust=False)
                if not hist.empty:
                    raw = float(hist["Close"].iloc[-1]); dc = {}
                    for idx_r,row in hist.iterrows():
                        c = row.get("Close")
                        if c is not None and c==c: dc[idx_r.strftime("%Y-%m-%d")] = float(c)
                    if dc: m1,ytd,y1 = calc_pcts(raw,dc,today)
            except: pass
        if m1 is not None or ytd is not None or y1 is not None:
            db_exec("INSERT OR IGNORE INTO prices_cache(symbol,updated_at) VALUES(?,datetime('now'))",(sym,))
            db_exec("UPDATE prices_cache SET m1_pct=?,ytd_pct=?,y1_pct=? WHERE symbol=?",(m1,ytd,y1,sym))
            done[0] += 1
    with ThreadPoolExecutor(max_workers=8) as ex: list(ex.map(fetch_one, symbols))
    print(f"  [period pcts] updated {done[0]}/{len(symbols)} symbols")


# ── Calculation functions ──────────────────────────────────────────────────────
def _xirr_newton(cashflows):
    if len(cashflows) < 2: return None
    d0 = cashflows[0][1]
    days = [(cf[1]-d0).days for cf in cashflows]
    def npv(rate): return sum(cf[0]/((1+rate)**(d/365.0)) for cf,d in zip(cashflows,days))
    def npv_d(rate): return sum(-(d/365.0)*cf[0]/((1+rate)**(d/365.0+1)) for cf,d in zip(cashflows,days))
    rate = 0.1
    for _ in range(200):
        f,df = npv(rate),npv_d(rate)
        if abs(df)<1e-12: break
        nxt = rate-f/df
        if abs(nxt-rate)<1e-8: rate=nxt; break
        rate=nxt
        if rate<-0.9999: rate=-0.9999
    return rate if abs(npv(rate))<1.0 else None

def calc_xirr_for_user(user_id):
    from datetime import datetime as _dt
    tickers = db_all("SELECT id FROM tickers WHERE user_id=?",(user_id,))
    if not tickers: return {"xirr":None}
    flows = []
    for t in tickers:
        for tx in db_all("SELECT type,date,shares,price,fee FROM transactions WHERE ticker_id=? ORDER BY date",(t["id"],)):
            try: d = _dt.fromisoformat(tx["date"]).replace(tzinfo=None)
            except: continue
            fee = tx["fee"] or 0
            if tx["type"]=="buy": flows.append((-(tx["shares"]*tx["price"]+fee),d))
            else: flows.append(((tx["shares"]*tx["price"]-fee),d))
    if not flows: return {"xirr":None}
    total_value = calc_portfolio_value_db(user_id)
    if total_value <= 0: return {"xirr":None}
    flows.append((total_value,_dt.now()))
    flows.sort(key=lambda x:x[1])
    rate = _xirr_newton(flows)
    return {"xirr": round(rate*100,4) if rate is not None else None}

def calc_rebalance_for_user(user_id, params):
    amount = float(params.get("amount",0)); is_deposit = params.get("mode","deposit")!="withdraw"
    allow_sell = bool(params.get("allowSell",False)); excluded = set(params.get("excluded",[]))
    tickers = db_all("SELECT id,symbol,name,yahoo_symbol FROM tickers WHERE user_id=? ORDER BY position,id",(user_id,))
    if not tickers: return {"rows":[],"totalToBuy":0,"totalToSell":0,"newTotal":0}
    prices = {}
    for t in tickers:
        sym = t["yahoo_symbol"] or t["symbol"]
        row = db_one("SELECT price FROM prices_cache WHERE symbol=?",(sym,))
        if row and row["price"]: prices[t["id"]] = row["price"]
    target_rows = db_all("SELECT ticker_id,target_pct FROM portfolio_targets WHERE user_id=?",(user_id,))
    targets = {r["ticker_id"]:r["target_pct"] for r in target_rows}
    positions = {}
    for t in tickers:
        tx_rows = db_all("SELECT type,shares,price FROM transactions WHERE ticker_id=? ORDER BY date",(t["id"],))
        shares=0.0; cost=0.0
        for tx in tx_rows:
            if tx["type"]=="buy": cost+=tx["shares"]*tx["price"]; shares+=tx["shares"]
            elif shares>0:
                avg=cost/shares; s=min(tx["shares"],shares); cost-=s*avg; shares-=s
        shares=max(0.0,shares); price=prices.get(t["id"]); value=shares*price if price else None
        positions[t["id"]]={"id":t["id"],"symbol":t["symbol"],"name":t["name"],"shares":shares,"cost":cost,"price":price,"value":value,"targetPct":targets.get(t["id"],0)}
    total_value=sum(p["value"] or 0 for p in positions.values())
    delta=amount if is_deposit else -amount; new_total=max(0.0,total_value+delta)
    incl_ids=[p["id"] for p in positions.values() if p["id"] not in excluded]
    excl_ids=[p["id"] for p in positions.values() if p["id"] in excluded]
    locked_value=sum(positions[i]["value"] or 0 for i in excl_ids)
    rebal_pool=new_total-locked_value
    incl_target_sum=sum(positions[i]["targetPct"] for i in incl_ids)
    rows=[]
    for pos in positions.values():
        is_excl=pos["id"] in excluded; target_pct=pos["targetPct"]
        cur_weight=(pos["value"] or 0)/total_value*100 if total_value>0 else 0
        if is_excl: ideal=pos["value"] or 0; diff=0.0; action="hold"
        else:
            scaled=target_pct/incl_target_sum if incl_target_sum>0 else 0
            ideal=rebal_pool*scaled; diff=ideal-(pos["value"] or 0)
            if not allow_sell and diff<0: diff=0.0; ideal=pos["value"] or 0; action="hold"
            else: action="buy" if diff>0.01 else "sell" if diff<-0.01 else "hold"
        shares_delta=diff/pos["price"] if pos["price"] and abs(diff)>0.01 else 0
        new_weight=ideal/new_total*100 if new_total>0 else 0
        rows.append({"id":pos["id"],"symbol":pos["symbol"],"name":pos["name"],"price":pos["price"],"value":pos["value"],"currentWeight":round(cur_weight,4),"newWeight":round(new_weight,4),"targetPct":target_pct,"ideal":round(ideal,2),"diff":round(diff,2),"shares":round(shares_delta,6),"action":action,"excluded":is_excl})
    total_to_buy=sum(r["diff"] for r in rows if r["action"]=="buy")
    total_to_sell=sum(-r["diff"] for r in rows if r["action"]=="sell")
    return {"rows":rows,"totalToBuy":round(total_to_buy,2),"totalToSell":round(total_to_sell,2),"newTotal":round(new_total,2),"totalValue":round(total_value,2)}


# ── HTTP Handler ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        if a and str(a[1]) not in ("200","304"): print(f"  {a[0]} {a[1]}")

    # ── Cookie / token helpers ───────────────────────────────────────────────
    def _client_ip(self):
        return (self.headers.get("CF-Connecting-IP") or
                self.headers.get("X-Forwarded-For","").split(",")[0].strip() or
                self.client_address[0])

    def _get_token(self):
        for part in self.headers.get("Cookie","").split(";"):
            part = part.strip()
            if part.startswith("session="): return part[8:]
        auth = self.headers.get("Authorization","")
        if auth.startswith("Bearer "): return auth[7:]
        return None

    def get_current_user(self):
        token = self._get_token()
        return verify_token(token) if token else None

    def require_auth(self):
        uid = self.get_current_user()
        if not uid: self.send_json({"error":"unauthorized"}, 401)
        return uid

    def set_session_cookie(self, token):
        self.send_header("Set-Cookie",
            f"session={token}; HttpOnly; SameSite=None; Secure; Max-Age={SESSION_TTL}; Path=/")

    def clear_session_cookie(self):
        self.send_header("Set-Cookie", "session=; HttpOnly; SameSite=None; Secure; Max-Age=0; Path=/")

    # ── Response helpers ─────────────────────────────────────────────────────
    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json;charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers(); self.wfile.write(body)

    def send_file(self, path, ctype):
        try:
            c = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", len(c))
            self.send_header("Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' "
                "https://unpkg.com https://cdnjs.cloudflare.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'")
            self.end_headers(); self.wfile.write(c)
        except FileNotFoundError:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ── GET ──────────────────────────────────────────────────────────────────
    def do_GET(self):
        p      = urllib.parse.urlparse(self.path)
        path   = p.path
        params = urllib.parse.parse_qs(p.query)

        # ── Auth endpoints ───────────────────────────────────────────────────
        if path == "/api/auth/me":
            uid = self.get_current_user()
            if not uid: self.send_json({"authenticated": False}); return
            u = get_user(uid)
            if not u: self.send_json({"authenticated": False}); return
            tk = self._get_token()
            self.send_json({"authenticated": True, "user_id": uid,
                           "username": u["username"], "role": u["role"], "token": tk}); return

        if path == "/api/auth/users":
            uid = self.require_auth()
            if not uid: return
            u = get_user(uid)
            if not u or u["role"] != "admin": self.send_json({"error":"forbidden"},403); return
            users = db_all("SELECT id,username,role,created_at FROM users")
            self.send_json({"users": [dict(u) for u in users]}); return

        # ── SPA: serve portfolio.html for all non-API routes ────────────────
        if not path.startswith("/api/"):
            ext = path.split(".")[-1].lower() if "." in path.split("/")[-1] else ""
            if ext in ("js","css","png","jpg","ico","svg","woff","woff2","ttf","map"):
                self.send_file(BASE_DIR / path.lstrip("/"), "application/octet-stream")
            else:
                self.send_file(BASE_DIR / "portfolio.html", "text/html;charset=utf-8")
            return

        # ── Data ─────────────────────────────────────────────────────────────
        if path == "/api/data":
            uid = self.require_auth()
            if not uid: return
            d = load_data(uid)
            d["euruah"] = round(fetch_yahoo("EURUAH=X").get("price", 40), 4)
            # XIRR
            try:
                settings = json.loads(db_one("SELECT settings FROM users WHERE id=?",(uid,))["settings"] or "{}")
                d["xirr"] = settings.get("xirr")
                if d["xirr"] is None:
                    d["xirr"] = calc_xirr_for_user(uid)["xirr"]
            except: d["xirr"] = None
            # Cached market prices
            try:
                all_syms = list(set(
                    [r["yahoo_symbol"] or r["symbol"] for r in db_all("SELECT yahoo_symbol,symbol FROM tickers WHERE user_id=?",(uid,))] +
                    [r["yahoo_symbol"] or r["symbol"] for r in db_all("SELECT yahoo_symbol,symbol FROM market_list WHERE user_id=?",(uid,))]
                ))
                if all_syms:
                    ph = ",".join("?"*len(all_syms))
                    rows = get_db().execute(f"SELECT symbol,price,day_pct,m1_pct,ytd_pct,y1_pct FROM prices_cache WHERE symbol IN ({ph})",all_syms).fetchall()
                    mp = {}
                    for r in rows:
                        if r["price"]: mp[r["symbol"]]={"price":r["price"],"dayPct":r["day_pct"],"m1Pct":r["m1_pct"],"ytdPct":r["ytd_pct"],"y1Pct":r["y1_pct"]}
                    if mp: d["marketPrices"] = mp
            except: pass
            self.send_json(d); return

        if path == "/api/ticker":
            self.send_json(fetch_market()); return

        if path == "/api/prices":
            raw = params.get("symbols",[""])[0]
            if not raw: self.send_json({"error":"missing"},400); return
            tlist = json.loads(raw); eurusd = get_eurusd()
            res = {"eurusd": round(eurusd,4), "prices": {}}
            lock = threading.Lock()
            _g=globals(); _to_eur=_g["to_eur"]; _eurusd=eurusd
            def fetch_one(t, _to_eur=_to_eur, _eurusd=_eurusd):
                s = t.get("yahooSymbol") or t.get("symbol")
                r = fetch_yahoo(s)
                if "error" in r:
                    with lock: res["prices"][str(t["id"])] = r; return
                cur   = r["currency"]
                price = round(_to_eur(r["price"], cur, _eurusd), 4)
                prev  = round(_to_eur(r["prev"],  cur, _eurusd), 4) if r.get("prev") else None
                dp    = r.get("dayChangePct")
                if dp is None and prev and prev > 0:
                    dp = round((price-prev)/prev*100, 2)
                with lock:
                    res["prices"][str(t["id"])] = {"price": price, "prev": prev,
                                                    "dayChangePct": dp, "currency":"EUR"}
                update_prices_cache(s, price, prev, dp)
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=15) as ex:
                list(ex.map(fetch_one, tlist))
            self.send_json(res); return

        if path == "/api/price":
            sym = params.get("symbol",[""])[0]
            if not sym: self.send_json({"error":"missing"},400); return
            eurusd = get_eurusd()
            r = fetch_yahoo(YAHOO_MAP.get(sym.upper(), sym))
            if "error" in r: self.send_json(r); return
            price = round(to_eur(r["price"], r["currency"], eurusd), 4)
            self.send_json({"price": price, "currency":"EUR",
                           "dayChangePct": r.get("dayChangePct"),
                           "eurusd": round(eurusd,4)}); return

        if path == "/api/snapshot":
            uid = self.require_auth()
            if not uid: return
            do_snapshot(uid); self.send_json({"ok":True}); return

        if path == "/api/seed-history":
            uid = self.require_auth()
            if not uid: return
            result = seed_history_from_yahoo(uid)
            self.send_json(result); return

        if path == "/api/targets":
            uid = self.require_auth()
            if not uid: return
            threading.Thread(target=update_analyst_targets, args=(uid,), daemon=True).start()
            self.send_json({"ok":True}); return

        if path == "/api/backups":
            uid = self.require_auth()
            if not uid: return
            backup_dir = BACKUP_DIR / uid
            backup_dir.mkdir(parents=True, exist_ok=True)
            files = sorted(backup_dir.glob("portfolio_*.json"), reverse=True)
            self.send_json({"backups": [f.name for f in files[:20]]}); return

        if path == "/api/restore":
            uid = self.require_auth()
            if not uid: return
            name = params.get("file",[""])[0]
            if not name or "/" in name or "\\" in name:
                self.send_json({"error":"invalid filename"},400); return
            src = BACKUP_DIR / uid / name
            if not src.exists(): self.send_json({"error":"not found"},404); return
            make_backup("pre-restore", uid)
            try:
                data = json.loads(src.read_text("utf-8"))
                save_data(data, uid)
                self.send_json({"ok":True,"restored":name})
            except Exception as e:
                self.send_json({"error":str(e)},400)
            return

        if path == "/api/market-prices":
            raw = params.get("symbols",[""])[0]
            if not raw: self.send_json({"error":"missing"},400); return
            ticker_list = json.loads(raw)
            eurusd = get_eurusd()
            results = {}; lock = threading.Lock()
            from datetime import date as _date, timedelta as _td, timezone as _tz

            def process_ticker(t):
                yahoo_sym = t.get("yahooSymbol") or t.get("symbol","")
                url = (f"https://query1.finance.yahoo.com/v8/finance/chart/"
                       f"{urllib.parse.quote(yahoo_sym)}?interval=1d&range=5y")
                try:
                    req = urllib.request.Request(url, headers=YAHOO_HEADERS)
                    with urllib.request.urlopen(req, timeout=12) as r:
                        j = json.loads(r.read().decode())
                    res = j["chart"]["result"][0]
                    meta = res["meta"]
                    cur  = meta.get("currency","USD").upper()
                    current_raw = meta.get("regularMarketPrice")
                    tss    = res.get("timestamp") or []
                    closes = res["indicators"]["quote"][0]["close"]
                    if not current_raw:
                        with lock: results[yahoo_sym] = {"error":"no price"}; return

                    def t2e(p): return to_eur(p, cur, eurusd) if p else None
                    date_close = {}
                    for ts, c in zip(tss, closes):
                        if c: date_close[datetime.fromtimestamp(ts,_tz.utc).strftime("%Y-%m-%d")] = c

                    today = _date.today()
                    def cc(td):
                        for i in range(30):
                            d = (td - _td(days=i)).isoformat()
                            if d in date_close: return date_close[d]
                        return None

                    dp_raw = meta.get("regularMarketChangePercent")
                    day_pct = round(dp_raw, 2) if dp_raw else None
                    if day_pct is None:
                        valid = [c for c in closes if c]
                        if len(valid) >= 2:
                            day_pct = round((valid[-1]-valid[-2])/valid[-2]*100, 2)

                    m1_c  = cc(today - _td(days=30))
                    ytd_c = cc(_date(today.year-1,12,31))
                    y1_c  = cc(today - _td(days=365))
                    def pct(a,b): return round((a-b)/b*100,2) if a and b else None
                    price_eur = t2e(current_raw)

                    with lock:
                        results[yahoo_sym] = {
                            "price":  round(price_eur, 2) if price_eur else None,
                            "dayPct": day_pct,
                            "m1Pct":  pct(current_raw, m1_c),
                            "ytdPct": pct(current_raw, ytd_c),
                            "y1Pct":  pct(current_raw, y1_c),
                        }
                    update_prices_cache(yahoo_sym, round(price_eur,2) if price_eur else None,
                                        None, day_pct)
                except Exception as e:
                    with lock: results[yahoo_sym] = {"error": str(e)[:40]}

            threads = [threading.Thread(target=process_ticker, args=(t,)) for t in ticker_list]
            for th in threads: th.start()
            for th in threads: th.join()
            self.send_json({"prices": results, "eurusd": round(eurusd,4)}); return

        if path=="/api/asset":
            sym = params.get("symbol",[""])[0]
            if not sym: self.send_json({"error":"missing"},400); return
            sym = resolve_yahoo_symbol(sym)
            eurusd = get_eurusd()
            from datetime import date as _date, timedelta as _td, datetime as _dt, timezone as _tz
            result = {}

            # ── EU→US mapping for fundamentals ──────────────────────────────
            EU_TO_US = {
                "APC":"AAPL","NVD":"NVDA","AMZ":"AMZN","MSF":"MSFT","ABEA":"GOOGL",
                "6RV":"APP","UT8":"UBER","3UX":"CLSK","1YD":"AVGO","NFC":"NFLX",
                "3V64":"V","6B0":"SOFI","7KY":"HOOD","BPE5":"BP.L","A00":"RGTI",
                "TL0":"TSLA","FB2A":"META","ADB":"ADBE","ORC":"ORCL","4S0":"NOW",
                "5Q5":"SNOW","8CF":"NET","MIGA":"MSTR","M44":"MARA","0YB0":"IONQ",
                "RQ0":"QBTS","MS51":"SMCI","1170":"ANET","LAR0":"LRCX","QCI":"QCOM",
                "MTE":"MU","1QZ":"COIN","PTX":"PLTR","639":"SPOT","307":"SHOP",
                "FOO":"CRM","5AP":"PANW","NKE":"NKE","MDO":"MCD","CCC3":"KO",
                "PFE":"PFE","LLY":"LLY","JNJ":"JNJ","UNH":"UNH","CMC":"JPM",
                "BRYN":"BRK-B","XONA":"XOM","YCP":"COP","AP4N":"RIOT","O9T":"ARM",
                "INL":"INTC","WDC":"WDC","12DA":"DELL","526":"MDB","0QF":"MRNA",
                "MLB1":"MELI","INN1":"ING","NMM":"NEM","ABR0":"B","HT3":"AU",
                "RIO1":"RIO","HCL":"HL","SII":"WPM","SHPX":"SHOP","ASME":"ASML",
                "SAP":"SAP","SIE":"SIEGY","ALV":"ALIZY","LHA":"DLAKY","AIR":"EADSY",
                "RRU":"RR.L","SSLN":"PSLV",
                # Additional mappings
                "BMW":"BMWYY","MBG":"MBGAF","VOW3":"VWAGY","DBK":"DB","CBK":"CRZBY",
                "DTE":"DTEGY","EOAN":"EONGY","RWE":"RWEOY","BAYN":"BAYRY","BAS":"BASFY",
                "IFX":"IFNNY","SEJ1":"SAFRY","MOH":"LVMUY","ESL":"ESLOY","2FE":"RACE",
                "CRIN":"UNCRY","AXA":"AXAHY","GZF":"ENGIY","SND":"SBGSY","CSF":"THLLY",
                "NOV":"NVO","R6C0":"SHEL","TOTB":"TTE","RHM":"RNMBY","ENR":"SMEGF",
                "HAG":"HAGHY","ADS":"ADDYY","PUM":"PUMSY","DHER":"DHERY",
            }
            base = sym.split(".")[0].upper()
            us_sym = EU_TO_US.get(base)
            # If not in static map, try Yahoo search (but only as last resort)
            if not us_sym:
                eu_suffixes = (".DE",".DU",".MU",".F",".SG",".AS",".MI",".PA",".BR",".VI")
                if any(sym.upper().endswith(s) for s in eu_suffixes):
                    try:
                        surl = f"https://query1.finance.yahoo.com/v1/finance/search?q={urllib.parse.quote(base)}&quotesCount=8&lang=en-US"
                        sreq = urllib.request.Request(surl, headers=YAHOO_HEADERS)
                        with urllib.request.urlopen(sreq, timeout=8) as sr:
                            sj = json.loads(sr.read().decode())
                        for q in sj.get("quotes",[]):
                            if q.get("exchange","") in ("NMS","NYQ","NGM","PCX","ASE","NGS"):
                                candidate = q.get("symbol","")
                                if candidate: us_sym = candidate; break
                    except: pass

            # ── Fetch chart data (5y daily + 2d intraday) ────────────────────
            def to_eur(p, currency=None):
                c = (currency or "USD").upper()
                if p is None: return None
                if c == "EUR": return p
                if c in ("GBp","GBX","PENCE"): return (p/100)*1.175
                if c == "GBP": return p*1.175
                return p/eurusd

            gbpeur = get_gbpeur()

            def tp_to_eur(tp, us_sym):
                """Convert target price considering the US symbol's currency."""
                if tp is None: return None
                tp = float(tp)
                if us_sym and us_sym.endswith(".L"):
                    # yfinance returns targetMeanPrice in GBp (pence) for LSE stocks
                    # e.g. BP.L target ~570 GBp = £5.70 * gbpeur = ~€6.56
                    result_gbp = tp / 100  # GBp to GBP
                    result_eur = result_gbp * gbpeur

                    return round(result_eur, 2)
                return round(tp / eurusd, 2)

            try:
                url = (f"https://query1.finance.yahoo.com/v8/finance/chart/"
                       f"{urllib.parse.quote(sym)}?interval=1d&range=5y")
                req = urllib.request.Request(url, headers=YAHOO_HEADERS)
                with urllib.request.urlopen(req, timeout=15) as r:
                    j = json.loads(r.read().decode())
                res  = j["chart"]["result"][0]
                meta = res["meta"]
                cur  = meta.get("currency","USD").upper()
                current_raw = meta.get("regularMarketPrice")
                timestamps  = res.get("timestamp") or []
                closes      = res["indicators"]["quote"][0]["close"]

                # Daily history — store in EUR
                history = []
                for ts, c in zip(timestamps, closes):
                    if c is None: continue
                    dt_s = _dt.fromtimestamp(ts, _tz.utc).strftime("%Y-%m-%dT%H:%M")
                    history.append({"t": dt_s, "v": round(to_eur(c, cur), 4)})

                # Intraday 5m for last 5 days (includes premarket + afterhours)
                # Use US symbol if available to get full pre/afterhours coverage
                intraday_sym = sym
                intraday_cur = cur
                if us_sym and cur == "EUR":
                    # EU symbol has no afterhours — use US symbol and convert
                    intraday_sym = us_sym
                    intraday_cur = "USD"
                try:
                    ui = (f"https://query1.finance.yahoo.com/v8/finance/chart/"
                          f"{urllib.parse.quote(intraday_sym)}?interval=5m&range=5d&includePrePost=true")
                    ri = urllib.request.Request(ui, headers=YAHOO_HEADERS)
                    with urllib.request.urlopen(ri, timeout=12) as rr:
                        ji = json.loads(rr.read().decode())
                    ri2  = ji["chart"]["result"][0]
                    tss_i = ri2.get("timestamp") or []
                    cls_i = ri2["indicators"]["quote"][0]["close"]
                    intraday = []
                    for ts2, c2 in zip(tss_i, cls_i):
                        if c2 is None: continue
                        dt_s = _dt.fromtimestamp(ts2, _tz.utc).strftime("%Y-%m-%dT%H:%M")
                        intraday.append({"t": dt_s, "v": round(to_eur(c2, intraday_cur), 4)})
                    if intraday:
                        first_intra_date = intraday[0]["t"][:10]
                        # Keep daily history intact, store intraday separately
                        history_daily = [h for h in history if h["t"][:10] < first_intra_date]
                        # Merge: daily for old data + intraday for recent
                        history = history_daily + intraday
                except: pass

                # Price changes (use EUR values from history)
                date_close = {h["t"][:10]: h["v"] for h in history if len(h["t"])>=10}
                today = _date.today()
                def get_close(days_ago):
                    for i in range(10):
                        d = (today - _td(days=days_ago+i)).isoformat()
                        if d in date_close: return date_close[d]
                    return None

                current_eur = to_eur(current_raw, cur)
                day_pct_raw = meta.get("regularMarketChangePercent") or meta.get("regularMarketChange")
                if day_pct_raw is not None and current_raw and current_raw > 0:
                    # regularMarketChange is absolute change, convert to pct if needed
                    if abs(day_pct_raw) > 100:  # it's absolute change, not pct
                        prev = current_raw - day_pct_raw
                        day_pct = round(day_pct_raw/prev*100, 2) if prev else 0
                    else:
                        day_pct = round(day_pct_raw, 2)
                else:
                    day_pct = None
                m1_c  = get_close(30)
                ytd_c = date_close.get(f"{today.year-1}-12-31") or get_close(today.timetuple().tm_yday)
                y1_c  = get_close(365)
                def pct(a, b): return round((a-b)/b*100, 2) if a and b else None

                # history_daily may not be defined if intraday failed
                h_daily = locals().get('history_daily', [h for h in history if 'T' not in h["t"] or h["t"][10]=='T' and len(h["t"])<=13])

                result = {
                    "price":  round(current_eur, 2) if current_eur else None,
                    "dayPct": day_pct,
                    "m1Pct":  pct(current_eur, m1_c),
                    "ytdPct": pct(current_eur, ytd_c),
                    "y1Pct":  pct(current_eur, y1_c),
                    "high52": round(to_eur(meta.get("fiftyTwoWeekHigh"), cur), 2) if meta.get("fiftyTwoWeekHigh") else None,
                    "low52":  round(to_eur(meta.get("fiftyTwoWeekLow"),  cur), 2) if meta.get("fiftyTwoWeekLow")  else None,
                    "volume": meta.get("regularMarketVolume"),
                    "history": history[-3000:],
                    "historyDaily": h_daily[-2000:],
                    "currency": "EUR",
                    "us_sym": us_sym or "",
                }
            except Exception as e:
                result["error"] = str(e)[:80]
                print(f"  [asset chart] {sym}: {e}")

            # ── Fundamentals via /v10/finance/quoteSummary ───────────────
            # Fix us_sym: if original symbol has no suffix, it IS the US symbol
            eu_sfx = (".DE",".DU",".MU",".F",".SG",".AS",".MI",".PA",".VI",".BR",".L")
            if not us_sym and not any(sym.upper().endswith(s) for s in eu_sfx):
                us_sym = sym  # e.g. AAPL, NVDA — already US
            fsym = us_sym or sym


            def eur_v(v):
                if v is None: return None
                try: return round(float(v)/eurusd, 2)
                except: return None

            def rv(d, k):
                v = d.get(k)
                return v.get("raw") if isinstance(v, dict) else v

            fund_ok = False
            mods = "summaryDetail,assetProfile,defaultKeyStatistics,financialData,recommendationTrend,earningsTrend"
            crumb = None

            # Step 1: get crumb (needed for authenticated endpoints)
            try:
                crumb_url = "https://query1.finance.yahoo.com/v1/test/getcrumb"
                cr = urllib.request.Request(crumb_url, headers={**YAHOO_HEADERS,
                    "Cookie": "tbla_id=1; B=abc123"})
                with urllib.request.urlopen(cr, timeout=8) as crr:
                    crumb = crr.read().decode().strip()
                    print(f"  [asset] crumb: {crumb[:10]}...")
            except Exception as e:
                print(f"  [asset] crumb failed: {e}")

            # Step 2: quoteSummary — try ETR symbol first, then US symbol
            # ETR symbol gives correct company name/description for EU-listed companies
            if crumb:
                syms_to_try = []
                if sym != fsym:
                    syms_to_try.append(sym)   # Try ETR symbol first (e.g. ABR0.DE)
                syms_to_try.append(fsym)       # Then US symbol (e.g. B for Barrick)
                for qsym in syms_to_try:
                    try:
                        furl = (f"https://query1.finance.yahoo.com/v10/finance/quoteSummary/"
                                f"{urllib.parse.quote(qsym)}?modules={mods}&crumb={urllib.parse.quote(crumb)}")
                        freq = urllib.request.Request(furl, headers=YAHOO_HEADERS)
                        with urllib.request.urlopen(freq, timeout=12) as fr:
                            fj = json.loads(fr.read().decode())
                        s  = (fj.get("quoteSummary",{}).get("result") or [None])[0]
                        if not s: continue
                        sd = s.get("summaryDetail",{})
                        ap = s.get("assetProfile",{})
                        ks = s.get("defaultKeyStatistics",{})
                        fd = s.get("financialData",{})
                        rt = s.get("recommendationTrend",{})
                        et = s.get("earningsTrend",{})
                        mc_raw = rv(sd,"marketCap") or rv(fd,"marketCap")
                        trend  = rt.get("trend") or [{}]
                        latest = trend[0] if trend else {}
                        analyst = {
                            "strongBuy":  latest.get("strongBuy",0),
                            "buy":        latest.get("buy",0),
                            "hold":       latest.get("hold",0),
                            "sell":       latest.get("sell",0),
                            "strongSell": latest.get("strongSell",0),
                            "mean":       rv(fd,"recommendationMean"),
                            "key":        fd.get("recommendationKey",""),
                        }
                        total = sum(analyst[k] for k in ["strongBuy","buy","hold","sell","strongSell"])
                        # Annual revenue from earningsTrend
                        revenues = []
                        for tr in (et.get("trend") or []):
                            per = tr.get("period","")
                            rev_avg = rv(tr.get("revenueEstimate",{}),"avg")
                            if rev_avg and per in ["-4y","-3y","-2y","-1y","0y"]:
                                revenues.append({"period":per,"v":round(float(rev_avg)/eurusd,0)})
                        desc = (ap.get("longBusinessSummary","") or "")[:600]
                        # If this is the ETR symbol and has no description, continue to US symbol
                        if not desc and qsym == sym and qsym != fsym:
                            print(f"  [asset] {qsym}: no description, trying US symbol")
                            continue
                        result.update({
                            "marketCap":     round(mc_raw/eurusd,0) if mc_raw else None,
                            "pe":            rv(sd,"trailingPE"),
                            "eps":           eur_v(rv(ks,"trailingEps")),
                            "dividendYield": round(rv(sd,"dividendYield")*100,2) if rv(sd,"dividendYield") else None,
                            "sector":        ap.get("sector",""),
                            "industry":      ap.get("industry",""),
                            "website":       ap.get("website",""),
                            "employees":     rv(ap,"fullTimeEmployees"),
                            "description":   desc,
                            "targetPrice":   eur_v(rv(fd,"targetMeanPrice")),
                            "analyst":       analyst,
                            "totalAnalysts": total,
                            "revenues":      revenues,
                        })
                        print(f"  [asset] ✓ {qsym}: PE={result.get('pe')}, sector={result.get('sector')}, analysts={total}")
                        fund_ok = True
                        break
                    except Exception as e:
                        print(f"  [asset] quoteSummary {qsym}: {e}")

            if not fund_ok:
                # Fallback: try yfinance if available
                try:
                    import yfinance as _yf
                    tk = _yf.Ticker(fsym)
                    info = tk.info or {}
                    mc = info.get("marketCap")
                    eps_raw = info.get("trailingEps")
                    tp_raw  = info.get("targetMeanPrice")
                    dy_raw = info.get("dividendYield")
                    # yfinance dividendYield is already a fraction (0.0044 = 0.44%)
                    # but sometimes it's already percent — cap at 30% to detect
                    if dy_raw and float(dy_raw) > 0.3:
                        dy = round(float(dy_raw), 2)  # already in percent
                    elif dy_raw:
                        dy = round(float(dy_raw) * 100, 2)  # convert fraction to percent
                    else:
                        dy = None
                    roe = info.get("returnOnEquity"); pm = info.get("profitMargins")
                    # yfinance stores analyst counts in recommendations
                    sb = info.get("strongBuy") or 0
                    b  = info.get("buy") or 0
                    h  = info.get("hold") or 0
                    s  = info.get("sell") or 0
                    ss = info.get("strongSell") or 0
                    # Try recommendations summary if counts are zero
                    if sb+b+h+s+ss == 0:
                        try:
                            rec = tk.recommendations
                            if rec is not None and not rec.empty:
                                latest = rec.iloc[-1] if len(rec) else None
                                if latest is not None:
                                    sb = int(latest.get("strongBuy",0) or 0)
                                    b  = int(latest.get("buy",0) or 0)
                                    h  = int(latest.get("hold",0) or 0)
                                    s  = int(latest.get("sell",0) or 0)
                                    ss = int(latest.get("strongSell",0) or 0)
                        except: pass
                    analyst_yf = {
                        "strongBuy":  sb, "buy": b, "hold": h,
                        "sell": s, "strongSell": ss,
                        "mean": info.get("recommendationMean"),
                        "key":  info.get("recommendationKey",""),
                    }
                    # Get revenues from financials
                    revenues = []
                    try:
                        import math
                        fins = tk.financials
                        if fins is not None and not fins.empty:
                            rev_row = None
                            for key in ["Total Revenue","Revenue","TotalRevenue"]:
                                if key in fins.index:
                                    rev_row = fins.loc[key]; break
                            if rev_row is not None:
                                for col in sorted(rev_row.index, reverse=True)[:5]:
                                    try:
                                        v = float(rev_row[col])
                                        if v and not math.isnan(v) and not math.isinf(v):
                                            yr = col.year if hasattr(col,"year") else str(col)[:4]
                                            revenues.append({"period": str(yr), "v": round(v/eurusd, 0)})
                                    except: pass
                    except: pass

                    result.update({
                        "marketCap":    round(mc/eurusd,0) if mc else None,
                        "pe":           info.get("trailingPE"),
                        "eps":          eur_v(eps_raw),
                        "dividendYield": dy,
                        "sector":       info.get("sector",""),
                        "industry":     info.get("industry",""),
                        "website":      info.get("website",""),
                        "employees":    info.get("fullTimeEmployees"),
                        "description":  (info.get("longBusinessSummary","") or "")[:600],
                        "targetPrice":  tp_to_eur(tp_raw, us_sym),
                        "analyst":      analyst_yf,
                        "totalAnalysts":info.get("numberOfAnalystOpinions",0) or 0,
                        "revenues":     revenues,
                    })
                    print(f"  [asset] ✓ yfinance {fsym}: PE={result.get('pe')}, sector={result.get('sector')}")
                    fund_ok = True
                except ImportError:
                    print(f"  [asset] yfinance not installed. Run: pip install yfinance")
                except Exception as e:
                    print(f"  [asset] yfinance error: {e}")

            if not fund_ok:
                print(f"  [asset] {fsym}: all fundamentals sources failed")
                result.update({"pe":None,"sector":"","description":"","dividendYield":None})

            # Replace any NaN/Inf with None for valid JSON
            # ── Premarket / After-hours ──────────────────────────────────
            try:
                pm = fetch_premarket(sym, eurusd)
                mkt = is_market_open(sym)
                result["preMarket"]     = pm.get("preMarket")
                result["preMarketPct"]  = pm.get("preMarketPct")
                result["afterHours"]    = pm.get("afterHours")
                result["afterHoursPct"] = pm.get("afterHoursPct")
                result["marketStatus"]  = mkt
            except Exception as e:
                print(f"  [premarket] {sym}: {e}")

            import math
            def sanitize(obj):
                if isinstance(obj, float):
                    if math.isnan(obj) or math.isinf(obj): return None
                    return obj
                if isinstance(obj, dict): return {k: sanitize(v) for k,v in obj.items()}
                if isinstance(obj, list): return [sanitize(i) for i in obj]
                return obj
            self.send_json(sanitize(result)); return

        self.send_response(404); self.end_headers()

    # ── POST ─────────────────────────────────────────────────────────────────
    def do_POST(self):
        p    = urllib.parse.urlparse(self.path)
        path = p.path
        n    = int(self.headers.get("Content-Length", 0))
        body_raw = self.rfile.read(n)

        # ── Auth ─────────────────────────────────────────────────────────────
        if path == "/api/auth/register":
            try: body = json.loads(body_raw)
            except: self.send_json({"error":"invalid json"},400); return
            username = body.get("username","").strip().lower()
            password = body.get("password","")
            if not username or len(username) < 3:
                self.send_json({"error":"username must be ≥3 chars"},400); return
            if len(password) < 6:
                self.send_json({"error":"password must be ≥6 chars"},400); return
            if get_user_by_username(username):
                self.send_json({"error":"username already taken"},409); return
            users_count = db_one("SELECT COUNT(*) as c FROM users")["c"]
            role    = "admin" if users_count == 0 else "user"
            uid     = secrets.token_hex(8)
            db_exec("INSERT INTO users(id,username,password,role) VALUES(?,?,?,?)",
                    (uid, username, hash_password(password), role))
            token = make_token(uid)
            self.send_response(200)
            self.send_header("Content-Type","application/json;charset=utf-8")
            self.set_session_cookie(token)
            resp = json.dumps({"ok":True,"user_id":uid,"username":username,"role":role,"token":token}).encode()
            self.send_header("Content-Length",len(resp))
            self.end_headers(); self.wfile.write(resp)
            print(f"  [auth] registered: {username} ({role})")
            return

        if path == "/api/auth/login":
            ip = self._client_ip()
            if not _login_limiter.is_allowed(ip, max_attempts=5, window_sec=60):
                self.send_json({"error":"too many login attempts, try again in 1 minute"},429); return
            try: body = json.loads(body_raw)
            except: self.send_json({"error":"invalid json"},400); return
            username = body.get("username","").strip().lower()
            password = body.get("password","")
            u = get_user_by_username(username)
            if not u or not verify_password(password, u["password"]):
                self.send_json({"error":"invalid username or password"},401); return
            token = make_token(u["id"])
            self.send_response(200)
            self.send_header("Content-Type","application/json;charset=utf-8")
            self.set_session_cookie(token)
            resp = json.dumps({"ok":True,"user_id":u["id"],"username":u["username"],"role":u["role"],"token":token}).encode()
            self.send_header("Content-Length",len(resp))
            self.end_headers(); self.wfile.write(resp)
            print(f"  [auth] login: {username}")
            return

        if path == "/api/auth/logout":
            self.send_response(200)
            self.send_header("Content-Type","application/json;charset=utf-8")
            self.clear_session_cookie()
            resp = json.dumps({"ok":True}).encode()
            self.send_header("Content-Length",len(resp))
            self.end_headers(); self.wfile.write(resp)
            return

        if path == "/api/auth/change-password":
            uid = self.require_auth()
            if not uid: return
            try: body = json.loads(body_raw)
            except: self.send_json({"error":"invalid json"},400); return
            old_pw = body.get("oldPassword","")
            new_pw = body.get("newPassword","")
            if len(new_pw) < 6:
                self.send_json({"error":"password must be ≥6 chars"},400); return
            u = get_user(uid)
            if not u or not verify_password(old_pw, u["password"]):
                self.send_json({"error":"wrong current password"},401); return
            db_exec("UPDATE users SET password=? WHERE id=?", (hash_password(new_pw), uid))
            self.send_json({"ok":True})
            print(f"  [auth] password changed: {u['username']}")
            return

        if path == "/api/auth/delete-user":
            uid = self.require_auth()
            if not uid: return
            u = get_user(uid)
            if not u or u["role"] != "admin":
                self.send_json({"error":"forbidden"},403); return
            try: body = json.loads(body_raw)
            except: self.send_json({"error":"invalid json"},400); return
            target_id = body.get("user_id","")
            if target_id == uid:
                self.send_json({"error":"cannot delete yourself"},400); return
            db_exec("DELETE FROM users WHERE id=?", (target_id,))
            self.send_json({"ok":True}); return

        # ── Data ─────────────────────────────────────────────────────────────
        if path == "/api/data":
            uid = self.require_auth()
            if not uid: return
            try:
                data = json.loads(body_raw.decode("utf-8"))
                # Auto-backup on structural changes
                try:
                    old_count = db_one("SELECT COUNT(*) as c FROM tickers WHERE user_id=?", (uid,))["c"]
                    new_count = len(data.get("tickers", []))
                    if abs(old_count - new_count) > 0:
                        make_backup("change", uid)
                except: pass
                save_data(data, uid)
                self.send_json({"ok":True})
            except Exception as e:
                self.send_json({"error":str(e)},400)
            return

        if path == "/api/backup":
            uid = self.require_auth()
            if not uid: return
            make_backup("manual", uid)
            self.send_json({"ok":True}); return

        if path == "/api/period-pcts":
            try: body_json = json.loads(body_raw)
            except: self.send_json({"error":"invalid json"},400); return
            symbols = body_json.get("symbols",[])
            if not symbols: self.send_json({"error":"missing"},400); return
            results = {}
            for sym in symbols:
                row = db_one("SELECT m1_pct,ytd_pct,y1_pct FROM prices_cache WHERE symbol=?",(sym,))
                if row: results[sym]={"m1Pct":row["m1_pct"],"ytdPct":row["ytd_pct"],"y1Pct":row["y1_pct"]}
            missing = [s for s in symbols if not results.get(s,{}).get("m1Pct")]
            if missing:
                threading.Thread(target=_update_period_pcts_for_symbols,args=(missing,),daemon=True).start()
            self.send_json({"pcts":results}); return

        if path == "/api/calc/xirr":
            uid = self.require_auth()
            if not uid: return
            self.send_json(calc_xirr_for_user(uid)); return

        if path == "/api/calc/rebalance":
            uid = self.require_auth()
            if not uid: return
            try: body_json = json.loads(body_raw)
            except: self.send_json({"error":"invalid json"},400); return
            self.send_json(calc_rebalance_for_user(uid, body_json)); return

        if path == "/api/refresh-prices":
            uid = self.require_auth()
            if not uid: return
            if not _can_user_refresh(uid):
                wait = _seconds_until_refresh(uid)
                self.send_json({"ok":False,"wait":wait}); return
            threading.Thread(target=refresh_prices,args=(uid,),daemon=True).start()
            self.send_json({"ok":True}); return

        self.send_response(404); self.end_headers()

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  Portfolio Tracker v3 (SQLite)")
    print("=" * 50)

    init_db()
    migrate_from_json()

    # Day start for all users
    for row in db_all("SELECT id FROM users"):
        try: do_day_start(row["id"])
        except: pass

    # Seed history in background if empty
    def _bg_seed():
        for row in db_all("SELECT id FROM users"):
            uid = row["id"]
            count = db_one("SELECT COUNT(*) as c FROM price_history WHERE user_id=?", (uid,))["c"]
            if count == 0:
                tickers = db_all("SELECT id FROM tickers WHERE user_id=?", (uid,))
                if tickers:
                    print(f"  [startup] seeding history for {uid}...")
                    seed_history_from_yahoo(uid)
    threading.Thread(target=_bg_seed, daemon=True).start()

    # Startup: refresh prices and period pcts
    def _startup_refresh():
        time.sleep(2)
        for row in db_all("SELECT id FROM users"):
            uid = row["id"]
            try: refresh_prices(uid)
            except: pass
        all_syms = set()
        for row in db_all("SELECT id FROM users"):
            for t in db_all("SELECT yahoo_symbol,symbol FROM tickers WHERE user_id=?",(row["id"],)):
                all_syms.add(t["yahoo_symbol"] or t["symbol"])
        if all_syms:
            _update_period_pcts_for_symbols(list(all_syms))
            print(f"  [startup] period pcts refreshed ({len(all_syms)} symbols)")
        # Cache XIRR
        for row in db_all("SELECT id FROM users"):
            uid = row["id"]
            try:
                xirr_result = calc_xirr_for_user(uid)
                settings = json.loads(db_one("SELECT settings FROM users WHERE id=?",(uid,))["settings"] or "{}")
                settings["xirr"] = xirr_result.get("xirr")
                db_exec("UPDATE users SET settings=? WHERE id=?",(json.dumps(settings),uid))
            except: pass
    threading.Thread(target=_startup_refresh, daemon=True).start()

    # Analyst targets in background
    threading.Thread(target=_update_all_targets_all_users, daemon=True).start()

    # Background price refresh
    threading.Thread(target=bg, daemon=True).start()

    try: ip = socket.gethostbyname(socket.gethostname())
    except: ip = "?"
    print(f"\n  Browser:  http://localhost:{PORT}")
    print(f"  Phone:    http://{ip}:{PORT}")
    print(f"  Database: {DB_PATH}")
    print(f"  Ctrl+C to stop\n" + "-" * 50)

    srv = HTTPServer(("", PORT), Handler)
    try: srv.serve_forever()
    except KeyboardInterrupt: print("\n  Stopped.")
