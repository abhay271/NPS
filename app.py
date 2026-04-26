import base64
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from flask import Flask, Response, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

state_lock = threading.Lock()
state = {
    "pipeline_status": "idle",
    "socket_log": [],
    "prepare_result": {},
    "chunks_sent": 0,
    "total_chunks": 0,
}

CHUNK_RE = re.compile(r"Chunk\s+(\d+)\s*/\s*(\d+)", re.IGNORECASE)


def _append_log(line: str) -> None:
    with state_lock:
        state["socket_log"].append(line)


def _set_status(status: str) -> None:
    with state_lock:
        state["pipeline_status"] = status


def _update_progress_from_line(line: str) -> None:
    m = CHUNK_RE.search(line)
    if not m:
        return
    sent = int(m.group(1))
    total = int(m.group(2))
    with state_lock:
        state["chunks_sent"] = sent
        state["total_chunks"] = total


def _maybe_capture_prepare_json(line: str) -> None:
    start = line.find("{")
    if start < 0:
        return
    maybe_json = line[start:].strip()
    try:
        obj = json.loads(maybe_json)
    except json.JSONDecodeError:
        return

    if not isinstance(obj, dict):
        return

    if obj.get("status") != "success":
        return

    keys = {"rsa_ciphertext_b64", "aes_ciphertext_b64", "pixel_diff", "sha256_hash"}
    if not keys.issubset(set(obj.keys())):
        return

    with state_lock:
        state["prepare_result"] = {
            "rsa_ciphertext_b64": obj.get("rsa_ciphertext_b64"),
            "aes_ciphertext_b64": obj.get("aes_ciphertext_b64"),
            "pixel_diff": obj.get("pixel_diff"),
            "sha256_hash": obj.get("sha256_hash"),
        }


def _sender_command(message: str) -> list[str]:
    exe = "sender.exe" if os.name == "nt" else "./sender"
    return [exe, message]


def _run_sender_pipeline(message: str) -> None:
    _set_status("running")

    cmd = _sender_command(message)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
    except Exception as exc:
        _append_log(f"[api] Failed to start sender: {exc}")
        _set_status("error")
        return

    if proc.stdout is not None:
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\r\n")
            if not line:
                continue
            _append_log(line)
            _update_progress_from_line(line)
            _maybe_capture_prepare_json(line)

    rc = proc.wait()
    if rc == 0:
        _set_status("complete")
    else:
        _append_log(f"[api] sender exited with code {rc}")
        _set_status("error")


def _decode_image_base64(image_base64: str) -> bytes:
    payload = image_base64.strip()
    if payload.startswith("data:"):
        comma = payload.find(",")
        if comma != -1:
            payload = payload[comma + 1 :]
    return base64.b64decode(payload)


@app.post("/api/send")
def api_send():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    image_base64 = data.get("image_base64")

    if not message:
        return jsonify({"status": "error", "message": "message is required"}), 400

    if image_base64:
        try:
            image_bytes = _decode_image_base64(str(image_base64))
            Path("images").mkdir(parents=True, exist_ok=True)
            Path("images/cover.png").write_bytes(image_bytes)
        except Exception as exc:
            return jsonify({"status": "error", "message": f"invalid image_base64: {exc}"}), 400

    with state_lock:
        state["pipeline_status"] = "running"
        state["socket_log"] = []
        state["prepare_result"] = {}
        state["chunks_sent"] = 0
        state["total_chunks"] = 0

    t = threading.Thread(target=_run_sender_pipeline, args=(message,), daemon=True)
    t.start()

    return jsonify({"status": "started"})


@app.get("/api/status")
def api_status():
    with state_lock:
        snapshot = {
            "pipeline_status": state["pipeline_status"],
            "socket_log": list(state["socket_log"]),
            "progress": {
                "chunks_sent": state["chunks_sent"],
                "total_chunks": state["total_chunks"],
            },
        }
    return jsonify(snapshot)


@app.get("/api/result")
def api_result():
    with state_lock:
        current_status = state["pipeline_status"]
        prepare = dict(state["prepare_result"])

    if current_status == "running":
        pending = {"status": "running", "message": "pipeline still running"}
        pending.update(prepare)
        return jsonify(pending)

    try:
        proc = subprocess.run(
            [sys.executable, "extract.py"],
            capture_output=True,
            text=True,
            check=False,
        )
        output = (proc.stdout or "").strip()
        if not output:
            result_data = {"status": "error", "message": "extract.py returned no output"}
        else:
            result_data = json.loads(output.splitlines()[-1])
    except Exception as exc:
        result_data = {"status": "error", "message": str(exc)}

    combined = dict(result_data)
    combined.update(prepare)
    return jsonify(combined)


@app.get("/api/stego-image")
def api_stego_image():
    path = Path("output/stego.png")
    if not path.exists():
        return jsonify({"status": "error", "message": "output/stego.png not found"}), 404
    b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    return jsonify({"image_base64": b64})


@app.get("/api/original-image")
def api_original_image():
    path = Path("images/cover.png")
    if not path.exists():
        return jsonify({"status": "error", "message": "images/cover.png not found"}), 404
    b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    return jsonify({"image_base64": b64})


@app.get("/api/stream")
def api_stream():
    def event_stream():
        index = 0
        while True:
            with state_lock:
                logs = list(state["socket_log"])
            while index < len(logs):
                line = logs[index]
                index += 1
                yield f"data: {line}\n\n"
            time.sleep(0.2)

    headers = {"Cache-Control": "no-cache"}
    return Response(event_stream(), mimetype="text/event-stream", headers=headers)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
