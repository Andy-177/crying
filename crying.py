import hashlib
import os
import time
import uuid

from flask import Flask, jsonify, redirect, render_template, request

app = Flask(__name__)

ENGINE = "cry-v3"
DEFAULT_DIFFICULTY = int(os.environ.get("CRYING_DIFFICULTY", "8"))
DEFAULT_HEAVY = int(os.environ.get("CRYING_HEAVY", "512"))
DEFAULT_MEMORY = int(os.environ.get("CRYING_MEMORY", "4"))
CHALLENGE_TTL = 600
MAX_DIFFICULTY = 128
MAX_ITERATIONS = 65536
MAX_MEMORY = 16
WORD_MASK = 0xFFFFFFFF

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


def issue_challenge(difficulty, steps, memory):
    cid = uuid.uuid4().hex
    seed = os.urandom(24).hex()
    challenges[cid] = {
        "seed": seed,
        "difficulty": difficulty,
        "iterations": steps,
        "memory": memory,
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


@app.route("/api/challenge")
def api_challenge():
    prune()
    try:
        difficulty = int(request.args.get("difficulty", DEFAULT_DIFFICULTY))
    except (TypeError, ValueError):
        difficulty = DEFAULT_DIFFICULTY
    difficulty = max(1, min(MAX_DIFFICULTY, difficulty))
    try:
        steps = int(request.args.get("heavy", DEFAULT_HEAVY))
    except (TypeError, ValueError):
        steps = DEFAULT_HEAVY
    steps = max(1, min(MAX_ITERATIONS, steps))
    try:
        memory = int(request.args.get("memory", DEFAULT_MEMORY))
    except (TypeError, ValueError):
        memory = DEFAULT_MEMORY
    memory = clamp_memory(memory)
    cid, seed = issue_challenge(difficulty, steps, memory)
    return jsonify({
        "ok": True,
        "challenge_id": cid,
        "seed": seed,
        "difficulty": difficulty,
        "iterations": steps,
        "memory": memory,
        "engine": ENGINE,
    })


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
    return render_template(
        "success.html",
        cid=cid,
        stats=proof,
        elapsed_sec=proof["elapsed_sec"],
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False)