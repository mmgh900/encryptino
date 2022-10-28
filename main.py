import json
import sqlite3
import time
from base64 import b64encode, b64decode
from datetime import datetime, timedelta
from sqlite3 import Error

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random.random import getrandbits
from Crypto.Util.Padding import pad, unpad
from fastapi import FastAPI, Request, Response
from pydantic import BaseModel

app = FastAPI()
connection = None
aes_key = pad(b"aes_key", AES.key_size[0])
aes_iv = pad(b"aes_iv", AES.block_size)


def hash_password(password, salt):
    return SHA256.new((password + salt).encode('utf-8')).hexdigest()


try:
    connection = sqlite3.connect('identifier.sqlite')
    print("Connection to SQLite DB successful")
except Error as e:
    print(f"The error '{e}' occurred")

cursor = connection.cursor()


class AuthForm(BaseModel):
    username: str
    password: str


@app.middleware("http")
async def authenticate(request: Request, call_next):
    if request.url.path == "/users" and request.method == "POST":
        return await call_next(request)
    elif request.url.path == "/sessions" and request.method == "POST":
        return await call_next(request)
    else:
        if request.headers.get("Authorization") and request.headers.get("Authorization").startswith("Bearer "):
            try:
                token = request.headers.get("Authorization").split(" ")[1]
                ct = b64decode(token)
                cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
                claims = unpad(cipher.decrypt(ct), AES.block_size)
                claims = claims.decode('utf-8')
                claims = json.loads(claims)
                request.state.username = claims.get('username')
                return await call_next(request)
            except Error as error:
                return Response(status_code=401, content="Invalid token")

        else:
            return Response(status_code=401, content="No token provided")


@app.post("/users")
async def signup(form: AuthForm):
    try:
        if form.username == "" or form.password == "":
            return {"message": "Please enter a username and password"}
        if cursor.execute(f"SELECT * FROM users WHERE username = '{form.username}'").fetchone() is not None:
            return {"message": "Username already exists"}

        salt = getrandbits(128)
        hex_salt = hex(salt)[2:]
        hashed_password = hash_password(form.password, hex_salt)
        key = RSA.generate(1024)
        public_key = b64encode(key.publickey().export_key('DER')).decode('utf-8')
        private_key = b64encode(key.export_key('DER')).decode('utf-8')
        cursor.execute(
            f"INSERT INTO users (username, password, salt, public_key, private_key) VALUES ('{form.username}', '{hashed_password}', '{hex_salt}', '{public_key}', '{private_key}')")

        connection.commit()
        print("Record inserted successfully into users table")
        return {"message": "User created successfully"}
    except Error as e:
        print(f"The error '{e}' occurred")
        return {"message": "User creation failed", "error": str(e)}


@app.post("/sessions")
async def login(form: AuthForm):
    try:
        if form.username == "" or form.password == "":
            return {"message": "Please enter a username and password"}
        user = cursor.execute(f"SELECT * FROM users WHERE username = '{form.username}'").fetchone()
        if user is None:
            return {"message": "Username does not exist"}
        hashed_password = hash_password(form.password, user[3])
        if hashed_password == user[2]:
            expiry = datetime.now() + timedelta(minutes=15)
            expiry_unix = time.mktime(expiry.timetuple())
            claims = {"username": form.username, "exp": expiry_unix}
            claims_bytes = json.dumps(claims).encode('utf-8')
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
            ct_bytes = cipher.encrypt(pad(claims_bytes, AES.block_size))
            token = b64encode(ct_bytes).decode('utf-8')

            return {"message": "Login successful", "token": token, "private_key": user[4]}
        print(f"hashed_password: {hashed_password} user[2]: {user[2]}")
        return {"message": "Incorrect password"}
    except Error as e:
        print(f"The error '{e}' occurred")
        return {"message": "Login failed", "error": str(e)}


@app.get("/users")
async def get_users(request: Request):
    try:
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        users = [{"username": user[1], "public_key": user[5]} for user in users]
        return {"users": users}
    except Error as e:
        print(f"The error '{e}' occurred")
        return {"message": "Failed to get users", "error": str(e)}


@app.post("/messages")
async def send_message(request: Request):
    try:
        data = await request.json()
        sender = request.state.username
        recipient = data.get("recipient")
        message = data.get("message")
        recipient_public_key = \
            cursor.execute(f"SELECT public_key FROM users WHERE username = '{recipient}'").fetchone()[0]
        recipient_public_key = RSA.import_key(b64decode(recipient_public_key))
        cipher = PKCS1_OAEP.new(recipient_public_key)
        ct = b64encode(cipher.encrypt(message.encode('utf-8'))).decode('utf-8')

        cursor.execute(
            f"INSERT INTO messages (sender, recipient, message) VALUES ('{sender}', '{recipient}', '{ct}')")
        connection.commit()
        print("Record inserted successfully into messages table")
        return {"message": "Message sent successfully"}
    except Error as e:
        print(f"The error '{e}' occurred")
        return {"message": "Failed to send message", "error": str(e)}


@app.get("/messages")
async def get_messages(request: Request):
    try:
        recipient = request.state.username
        raw_messages = cursor.execute(f"SELECT * FROM messages WHERE recipient = '{recipient}'").fetchall()
        private_key = cursor.execute(f"SELECT private_key FROM users WHERE username = '{recipient}'").fetchone()[0]
        private_key = RSA.import_key(b64decode(private_key))
        cipher = PKCS1_OAEP.new(private_key)
        messages = []
        for message in raw_messages:
            message = {"sender": message[1], "message": cipher.decrypt(b64decode(message[3])).decode('utf-8')}
            messages.append(message)

        return {"messages": raw_messages}
    except Error as e:
        print(f"The error '{e}' occurred")
        return {"message": "Failed to get messages", "error": str(e)}


@app.get("/messages/{id}/decrypted")
async def get_decrypted_message(request: Request, id: int):
    try:
        recipient = request.state.username
        raw_message = cursor.execute(f"SELECT * FROM messages WHERE recipient = '{recipient}' AND id = {id}").fetchone()
        private_key = cursor.execute(f"SELECT private_key FROM users WHERE username = '{recipient}'").fetchone()[0]
        private_key = RSA.import_key(b64decode(private_key))
        cipher = PKCS1_OAEP.new(private_key)
        message = {"sender": raw_message[1], "message": cipher.decrypt(b64decode(raw_message[3])).decode('utf-8')}
        return {"message": message}
    except Error as e:
        print(f"The error '{e}' occurred")
        return {"message": "Failed to get message", "error": str(e)}
