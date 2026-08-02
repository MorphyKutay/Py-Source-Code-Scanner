import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"


@dataclass
class User:
    id: int
    name: str


def fetch_user(cursor, user_id: int) -> User:
    cursor.execute("SELECT id, name FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    return User(*row)


def strong_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def to_json(payload: dict) -> str:
    return json.dumps(payload)


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return json.load(f)


def list_files() -> str:
    result = subprocess.run(["ls", "-la"], capture_output=True, text=True)
    return result.stdout


def call_api(session, base_url: str):
    return session.get(f"{base_url}/status")
