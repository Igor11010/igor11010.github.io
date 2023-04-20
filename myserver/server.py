import hmac
import hashlib
import base64
import json
from typing import Optional
from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "334a855f4cfc49d8d41f5a7a8c83ddb02b38f59ebf77632291ca366d46359fed"

PASSWORD_SALT = "ea1f68c7765b62c0a971a3202d8a4ca7c73490a9d1e8260f588f37c192ee8461"

def sign_data(data: str) -> str:
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_encoded: str) -> Optional[str]:
    username_base64, sign = username_encoded.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256( (password + PASSWORD_SALT).encode() ).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash

users = {
    "igorrobototechnic@gmail.com": {
        "name": "Igor",
        "password": "91ef70a6c6d4f4ccc9485898b8865f873df25a03e8e634e7cc4f5bafcfc61ba4",
        "balance": "100_000"
    },
    "olegprogrammer@gmail.com": {
        "name": "Oleg",
        "password": "790192a4315b32df66fa0ce443bcd318941c801f9589e82e7ddb49de952cda34",
        "balance": "100_000"
    }
}

@app.get("/")
def index_page(username: Optional[str]=Cookie(default=None)):
    with open('temp/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try: 
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(f"Hello, {users[valid_username]['name']}!", media_type="text/html")

@app.post("/login")
def process_login_page(data: dict=Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "I don't know you!"
            }), 
            media_type="application/json")
    responce = Response(
        json.dumps({
            "success": True,
            "message": f"Hello, {user['name']}<br /> Balance {user['balance']}"
        }),
        media_type="application/json")
    username_encoded = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    responce.set_cookie(key="username", value=username_encoded)
    return responce