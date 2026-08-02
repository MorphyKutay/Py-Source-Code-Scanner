import os
import pickle
import ssl
import subprocess
import hashlib
import yaml
import jwt
import requests
from flask import Flask, redirect, request
from django.utils.safestring import mark_safe

app = Flask(__name__)
DEBUG = True


def run_user_command(user_input):
    os.system(user_input)
    subprocess.run(user_input, shell=True)
    return eval(user_input)


def load_session(raw_bytes):
    return pickle.loads(raw_bytes)


def load_config(path):
    with open(path) as f:
        return yaml.load(f)


def render(html_fragment):
    return mark_safe(html_fragment)


def read_user_file():
    with open(request.args.get("file")) as f:
        return f.read()


def fetch_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def weak_checksum(data):
    return hashlib.md5(data).hexdigest()


def call_internal_api(base_url):
    return requests.get(f"{base_url}/status", verify=False)


def insecure_context():
    return ssl._create_unverified_context()


def go_to_next(request):
    return redirect(request.args.get("next"))


def open_permissions(path):
    os.chmod(path, 0o777)


def decode_token(token):
    return jwt.decode(token, verify=False)


password = "hunter2"
DB_PASSWORD = "supersecret"
STRIPE_API_KEY = "sk_live_abcdefghijklmnop"
aws_key = "AKIAABCDEFGHIJKLMNOP"
private_key = "-----BEGIN RSA PRIVATE KEY-----"
slack_token = "xoxb-1234567890-abcdefghij"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
