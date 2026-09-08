import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import string
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, redirect, render_template, request

APP_DIR = Path(sys.argv[0]).parent.resolve()

app = Flask(__name__)

ENGINE = "cry-v3"
CHALLENGE_TTL = 600
MAX_DIFFICULTY = 128
MAX_ITERATIONS = 65536
MAX_MEMORY = 16
WORD_MASK = 0xFFFFFFFF

DEFAULTS = {
    "difficulty": 8,
    "heavy": 512,
    "memory": 4,
    "workers": 32,
    "interval_ms": 500,
    "chunk": 64,
    "passkey": True,
    "keymap": True,
}

CONFIG = dict(DEFAULTS)
PASSKEY_FILE = APP_DIR / "passkey.txt"
KEYMAP_FILE = APP_DIR / "keymap.db"
_CONFIG_FILE = APP_DIR / "config.json"
if _CONFIG_FILE.is_file():
    try:
        with open(_CONFIG_FILE, "r", encoding="utf-8") as _f:
            _user_cfg = json.load(_f)
        if isinstance(_user_cfg, dict):
            _cfg_passkey = _user_cfg.get("passkey")
            if _cfg_passkey is not None:
                CONFIG["passkey"] = bool(_cfg_passkey)
            _cfg_keymap = _user_cfg.get("keymap")
            if _cfg_keymap is not None:
                CONFIG["keymap"] = bool(_cfg_keymap)
            _section = _user_cfg.get("cry")
            if not isinstance(_section, dict):
                _section = _user_cfg
            for _k in DEFAULTS:
                if _k in _section:
                    CONFIG[_k] = _section[_k]
    except (OSError, ValueError):
        pass
else:
    try:
        with open(_CONFIG_FILE, "w", encoding="utf-8") as _f:
            json.dump({
                "passkey": CONFIG["passkey"],
                "keymap": CONFIG["keymap"],
                "cry": {_k: CONFIG[_k] for _k in DEFAULTS if _k not in ("passkey", "keymap")},
            }, _f, ensure_ascii=False, indent=2)
            _f.write("\n")
    except OSError:
        pass

PASSKEY = ""
if CONFIG["passkey"]:
    try:
        if PASSKEY_FILE.is_file():
            PASSKEY = PASSKEY_FILE.read_text("utf-8", errors="replace").strip()
        if not PASSKEY:
            PASSKEY = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(256))
            PASSKEY_FILE.write_text(PASSKEY, "utf-8")
    except OSError:
        PASSKEY = ""


def _keymap_unique(existing):
    while True:
        k = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(256))
        if k not in existing:
            return k


def init_keymap():
    if not CONFIG.get("passkey"):
        return
    try:
        conn = sqlite3.connect(str(KEYMAP_FILE))
        conn.execute("CREATE TABLE IF NOT EXISTS keymap (domain TEXT PRIMARY KEY, priv_key TEXT)")
        conn.execute("DELETE FROM keymap WHERE domain IS NULL OR TRIM(domain) = ''")
        rows = conn.execute("SELECT domain, priv_key FROM keymap").fetchall()
        existing = {k for _, k in rows if k}
        for d, k in rows:
            if not k:
                nk = _keymap_unique(existing)
                conn.execute("UPDATE keymap SET priv_key = ? WHERE domain = ?", (nk, d))
                existing.add(nk)
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass


def resolve_from_key(href_target):
    try:
        parts = urlsplit(href_target)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return ""
    host = parts.hostname.lower()
    best = ("", 0)
    exact = ""
    try:
        conn = sqlite3.connect(str(KEYMAP_FILE))
        rows = conn.execute("SELECT domain, priv_key FROM keymap").fetchall()
        conn.close()
    except sqlite3.Error:
        rows = ()
    host = host[:-1] if host.endswith(".") else host
    for d, k in rows:
        if not d or not k:
            continue
        dl = d.lstrip(".").lower()
        if dl == host:
            exact = k
        if d.startswith(".") and host.endswith(d.lower()):
            if len(d) > best[1]:
                best = (k, len(d))
    return exact or best[0]


init_keymap()

challenges = {}
solutions = {}


def leading_zero_bits(hexdigest):
    count = 0
    for ch in hexdigest:
        nib = int(ch, 16)
        if nib == 0:
            count += 4
            continue
        for mask in (8, 4, 2, 1):
            if nib & mask:
                return count
            count += 1
    return count


def clamp_memory(mb):
    mb = max(1, min(MAX_MEMORY, mb))
    while mb & (mb - 1):
        mb &= mb - 1
    return mb


def prune():
    now = time.time()
    stale = [cid for cid, c in list(challenges.items()) if now - c["issued_at"] > CHALLENGE_TTL]
    for cid in stale:
        challenges.pop(cid, None)
        solutions.pop(cid, None)


def issue_challenge(difficulty, steps, memory, from_url="", from_mode="", challenge_code=""):
    cid = uuid.uuid4().hex
    seed = os.urandom(24).hex()
    challenges[cid] = {
        "seed": seed,
        "difficulty": difficulty,
        "iterations": steps,
        "memory": memory,
        "from_url": from_url,
        "from_mode": from_mode,
        "challenge_code": challenge_code,
        "issued_at": time.time(),
    }
    return cid, seed


def expand_words(seed, nonce, num_words):
    words = []
    prev = hashlib.sha256("{}:{}".format(seed, nonce).encode("utf-8")).hexdigest()
    while len(words) < num_words:
        take = min(8, num_words - len(words))
        for i in range(take):
            words.append(int(prev[i * 8:(i * 8) + 8], 16))
        prev = hashlib.sha256(prev.encode("utf-8")).hexdigest()
    return words


def cryv3(seed, nonce, steps, memory):
    num_words = memory << 18
    mask = num_words - 1
    pages_mask = (num_words >> 10) - 1
    words = expand_words(seed, nonce, num_words)

    a = (0x9E3779B9 ^ words[0]) & WORD_MASK
    pos = 0x2545F491 & mask
    addr = pos

    for i in range(steps):
        page = (i * 3) & pages_mask
        off = (pos + a) & 1023
        addr = (page << 10) | off
        w = words[addr]
        if a & 1:
            pos = (pos + ((w ^ (a >> 13)) & WORD_MASK)) & mask
        else:
            pos = (pos ^ ((w + 0x9E3779B9) & WORD_MASK)) & mask
        if w & 0x80000000:
            a = ((a << 7) ^ (w >> 3)) & WORD_MASK
        else:
            a = ((a ^ ((w << 9) & WORD_MASK) ^ (w >> 15)) & WORD_MASK)
        if a & 0x10000:
            a = ((a >> 16) ^ ((w << 16) & WORD_MASK)) & WORD_MASK
        else:
            a = (a ^ w) & WORD_MASK
        words[addr] = a

    hexes = "%08x%08x%08x%08x" % (
        words[addr] & WORD_MASK,
        words[(pos ^ a) & mask] & WORD_MASK,
        words[(a ^ 0x9E3779B9) & mask] & WORD_MASK,
        words[(pos + 0x1F2E3D4B) & mask] & WORD_MASK,
    )
    return hashlib.sha256(hexes.encode("utf-8")).hexdigest()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/from/<path:url>")
def from_url(url):
    qs = request.query_string.decode("utf-8", "replace")
    target = url if not qs else url + "?" + qs
    resp = redirect("/")
    if target and len(target) <= 2048:
        resp.set_cookie("crying_from", target, max_age=1800, path="/", httponly=True)
    return resp


@app.route("/session")
def session_gate():
    if not CONFIG["passkey"]:
        return jsonify({
            "ok": False,
            "message": "passkey 未开启，无法使用 /session",
        }), 403
    code = request.args.get("challenge_code", "")
    frm = request.args.get("from", "")
    resp = redirect("/")
    if isinstance(code, str) and code and len(code) <= 2048:
        resp.set_cookie("crying_sess_code", code, max_age=1800, path="/", httponly=True)
    if isinstance(frm, str) and frm and len(frm) <= 2048:
        resp.set_cookie("crying_sess_from", frm, max_age=1800, path="/", httponly=True)
    return resp


@app.route("/api/challenge")
def api_challenge():
    prune()
    difficulty = max(1, min(MAX_DIFFICULTY, int(CONFIG["difficulty"])))
    steps = max(1, min(MAX_ITERATIONS, int(CONFIG["heavy"])))
    memory = clamp_memory(int(CONFIG["memory"]))
    workers = max(1, min(64, int(CONFIG["workers"])))
    interval_ms = max(50, int(CONFIG["interval_ms"]))
    chunk = max(16, int(CONFIG["chunk"]))
    sess_code = request.cookies.get("crying_sess_code", "")
    sess_from = request.cookies.get("crying_sess_from", "")
    if not isinstance(sess_code, str) or len(sess_code) > 2048:
        sess_code = ""
    if not isinstance(sess_from, str) or len(sess_from) > 2048:
        sess_from = ""
    from_cookie = request.cookies.get("crying_from", "")
    if not isinstance(from_cookie, str) or len(from_cookie) > 2048:
        from_cookie = ""
    if sess_code and sess_from:
        from_url, from_mode, challenge_code = sess_from, "session", sess_code
    elif from_cookie:
        from_url, from_mode, challenge_code = from_cookie, "from", ""
    else:
        from_url, from_mode, challenge_code = "", "", ""
    cid, seed = issue_challenge(difficulty, steps, memory, from_url, from_mode, challenge_code)
    resp = jsonify({
        "ok": True,
        "challenge_id": cid,
        "seed": seed,
        "difficulty": difficulty,
        "iterations": steps,
        "memory": memory,
        "workers": workers,
        "interval_ms": interval_ms,
        "chunk": chunk,
        "engine": ENGINE,
    })
    resp.set_cookie("crying_from", "", expires=0, max_age=0, path="/", httponly=True)
    resp.set_cookie("crying_sess_code", "", expires=0, max_age=0, path="/", httponly=True)
    resp.set_cookie("crying_sess_from", "", expires=0, max_age=0, path="/", httponly=True)
    return resp


@app.route("/api/verify", methods=["POST"])
def api_verify():
    body = request.get_json(silent=True) or {}
    cid = body.get("challenge_id", "")
    nonce = body.get("nonce", "")

    challenge = challenges.get(cid)
    if challenge is None:
        return jsonify({"ok": False, "message": "任务不存在或已过期"}), 404
    if not isinstance(nonce, str) or not nonce.isdigit() or len(nonce) > 30:
        return jsonify({"ok": False, "message": "nonce 无效"}), 400

    difficulty = challenge["difficulty"]
    steps = challenge["iterations"]
    memory = challenge["memory"]
    digest = cryv3(challenge["seed"], nonce, steps, memory)
    zeros = leading_zero_bits(digest)

    if zeros < difficulty:
        return jsonify({
            "ok": False,
            "message": "工作量不足：{} / {} bit".format(zeros, difficulty),
        }), 422

    total_attempts = int(body.get("total_attempts", 0))
    winner_worker = int(body.get("winner_worker", 0))
    winner_index = int(body.get("winner_index", total_attempts))

    replay_start = time.perf_counter()
    cryv3(challenge["seed"], nonce, steps, memory)
    replay_ms = int((time.perf_counter() - replay_start) * 1000)

    elapsed_sec = round(time.time() - challenge["issued_at"], 2)
    from_url = challenge.get("from_url", "")
    from_mode = challenge.get("from_mode", "")
    challenge_code = challenge.get("challenge_code", "")

    solutions[cid] = {
        "difficulty": difficulty,
        "iterations": steps,
        "memory": memory,
        "total_attempts": total_attempts,
        "winner_worker": winner_worker,
        "winner_index": winner_index,
        "winner_digest": digest,
        "replay_ms": replay_ms,
        "elapsed_sec": elapsed_sec,
        "from_url": from_url,
        "from_mode": from_mode,
        "challenge_code": challenge_code,
        "solved_at": time.time(),
    }
    challenges.pop(cid, None)

    return jsonify({
        "ok": True,
        "message": "验证通过",
        "success_url": "/success?cid=" + cid,
    })


@app.route("/success")
def success():
    cid = request.args.get("cid", "")
    proof = solutions.get(cid)
    if proof is None:
        return redirect("/")
    from_url = proof.get("from_url", "")
    from_mode = proof.get("from_mode", "")
    challenge_code = proof.get("challenge_code", "")
    visit_href = from_url
    if from_url and from_mode == "session" and PASSKEY:
        sign = hmac.new(
            PASSKEY.encode("utf-8"), challenge_code.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        visit_href = "{}/crying?sign={}".format(from_url, sign)
    elif CONFIG["passkey"] and from_url and CONFIG["keymap"]:
        priv_key = resolve_from_key(from_url)
        if priv_key:
            passcode = hmac.new(
                PASSKEY.encode("utf-8"), priv_key.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            visit_href = "{}/crying?passcode={}".format(from_url, passcode)
        else:
            visit_href = from_url
    return render_template(
        "success.html",
        cid=cid,
        stats=proof,
        elapsed_sec=proof["elapsed_sec"],
        from_url=from_url,
        visit_href=visit_href,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False)