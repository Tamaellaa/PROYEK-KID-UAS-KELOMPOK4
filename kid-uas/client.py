# File dari sisi client
# Digunakan untuk membuat key, pesan, dan signature

import base64
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# =========================================================
# PILIH ALGORITMA
# =========================================================
# Ganti ke "secp256k1" jika ingin pakai EC
ALGORITHM = "ed25519"


# =========================================================
# GENERATE KEY
# =========================================================
if ALGORITHM == "ed25519":
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

elif ALGORITHM == "secp256k1":
    priv_key = ec.generate_private_key(
        ec.SECP256K1(),
        backend=default_backend()
    )
    pub_key = priv_key.public_key()

else:
    raise ValueError("Algoritma tidak didukung")


# =========================================================
# SIMPAN KEY KE FILE
# =========================================================
with open("client_private.pem", "wb") as f:
    f.write(
        priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

with open("client_public.pem", "wb") as f:
    f.write(
        pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


# =========================================================
# BUAT PESAN RAHASIA
# =========================================================
message = "Hai! Saya adalah client anda, ini adalah data eksperimen rahasia Vegapunk"
message_bytes = message.encode()


# =========================================================
# BUAT SIGNATURE
# =========================================================
if ALGORITHM == "ed25519":
    signature = priv_key.sign(message_bytes)

elif ALGORITHM == "secp256k1":
    signature = priv_key.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA256())
    )


signature_b64 = base64.b64encode(signature).decode()


# =========================================================
# OUTPUT UNTUK USER
# =========================================================
print("=== CLIENT SIDE OUTPUT ===")
print("Algorithm:", ALGORITHM)
print("Message:", message)
print("Signature (base64):")
print(signature_b64)
print("\nPublic key disimpan di: client_public.pem")
print("Private key disimpan di: client_private.pem")