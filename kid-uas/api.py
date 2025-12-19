# =========================================================
# Security Service API
# =========================================================

from fastapi import (
    FastAPI,
    HTTPException,
    UploadFile,
    File,
    Form,
    Security
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from enum import Enum
import os
import base64
import secrets
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


# =========================================================
# ALGORITHM ENUM (UNTUK DROPDOWN SWAGGER)
# =========================================================
class SignatureAlgorithm(str, Enum):
    ed25519 = "ed25519"
    secp256k1 = "secp256k1"
    secp256r1 = "secp256r1"


# =========================================================
# FASTAPI INIT
# =========================================================
app = FastAPI(
    title="Security Service",
    version="1.0.0",
    description="Punk Records Security API - Vegapunk"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


# =========================================================
# STORAGE
# =========================================================
KEY_DIR = "stored_keys"
os.makedirs(KEY_DIR, exist_ok=True)

SESSIONS = {}   # token -> username


# =========================================================
# HELPER
# =========================================================
def check_token(token: str):
    if token not in SESSIONS:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return SESSIONS[token]


# =========================================================
# BASIC ENDPOINTS
# =========================================================
@app.get("/")
async def index():
    return {
        "message": "Hello world! Visit http://localhost:8080/docs for API UI."
    }


@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }


# =========================================================
# LOGIN
# =========================================================
@app.post("/login")
async def login(username: str = Form(...)):
    token = secrets.token_hex(16)
    SESSIONS[token] = username

    return {
        "access_token": token,
        "token_type": "bearer"
    }


# =========================================================
# STORE PUBLIC KEY
# =========================================================
@app.post("/store")
async def store_pubkey(
    username: str = Form(...),
    algorithm: SignatureAlgorithm = Form(...),
    file: UploadFile = File(...)
):
    try:
        key_data = await file.read()
        serialization.load_pem_public_key(key_data)

        path = os.path.join(KEY_DIR, f"{username}_{algorithm}.pem")
        with open(path, "wb") as f:
            f.write(key_data)

    except Exception:
        raise HTTPException(status_code=400, detail="Public key tidak valid")

    return {
        "message": "Public key berhasil disimpan",
        "user": username,
        "algorithm": algorithm
    }

# =========================================================
# VERIFY SIGNATURE
# =========================================================
@app.post("/verify")
async def verify(
    username: str = Form(...),
    algorithm: SignatureAlgorithm = Form(...),
    message: str = Form(...),
    signature: str = Form(...)
):
    key_path = os.path.join(KEY_DIR, f"{username}_{algorithm}.pem")

    if not os.path.exists(key_path):
        raise HTTPException(status_code=404, detail="Public key tidak ditemukan")

    with open(key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        sig = base64.b64decode(signature)
        msg = message.encode()

        if algorithm == SignatureAlgorithm.ed25519:
            public_key.verify(sig, msg)

        elif algorithm in (
            SignatureAlgorithm.secp256k1,
            SignatureAlgorithm.secp256r1
        ):
            public_key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))

        return {"message": "Signature VALID", "valid": True}

    except InvalidSignature:
        return {"message": "Signature TIDAK VALID", "valid": False}


# =========================================================
# RELAY MESSAGE (PROTECTED → 🔓 AUTHORIZE)
# =========================================================
@app.post("/relay")
async def relay(
    sender: str = Form(...),
    receiver: str = Form(...),
    algorithm: SignatureAlgorithm = Form(...),
    message: str = Form(...),
    signature: str = Form(...),
    token: str = Security(oauth2_scheme)
):
    user = check_token(token)

    if user != sender:
        raise HTTPException(status_code=403, detail="Token tidak sesuai dengan sender")

    key_path = os.path.join(KEY_DIR, f"{sender}_{algorithm}.pem")
    if not os.path.exists(key_path):
        raise HTTPException(status_code=404, detail="Public key pengirim tidak ditemukan")

    with open(key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        sig = base64.b64decode(signature)
        msg = message.encode()

        if algorithm == SignatureAlgorithm.ed25519:
            public_key.verify(sig, msg)

        elif algorithm in (
            SignatureAlgorithm.secp256k1,
            SignatureAlgorithm.secp256r1
        ):
            public_key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))

    except InvalidSignature:
        raise HTTPException(status_code=400, detail="Signature tidak valid")

    return {
        "message": "Pesan berhasil diteruskan",
        "from": sender,
        "to": receiver,
        "content": message
    }
