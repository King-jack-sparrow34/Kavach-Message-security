import streamlit as st
from PIL import Image
import io, os, time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import random

st.markdown("""
<style>

/* ===== AI HUD CORE ===== */
.ai-hud {
    position: fixed;
    right: 28px;
    bottom: 28px;
    width: 280px;
    height: 180px;
    background: rgba(0, 15, 12, 0.92);
    border: 1px solid rgba(0,255,179,0.5);
    border-radius: 18px;
    padding: 16px;
    box-shadow:
        0 0 30px rgba(0,255,179,0.25),
        inset 0 0 20px rgba(0,255,179,0.08);
    z-index: 999;
}

/* ===== AI HEADER ===== */
.ai-title {
    font-size: 0.9rem;
    letter-spacing: 1.5px;
    margin-bottom: 8px;
    text-shadow: 0 0 8px #00ffb3;
}

/* ===== AI STATUS ===== */
.ai-status {
    font-size: 0.8rem;
    opacity: 0.85;
    line-height: 1.5;
}

/* ===== AI PULSE ===== */
.ai-core {
    width: 14px;
    height: 14px;
    background: #00ffb3;
    border-radius: 50%;
    box-shadow: 0 0 18px #00ffb3;
    animation: aiPulse 1.8s infinite;
    margin-bottom: 10px;
}

@keyframes aiPulse {
    0%   { transform: scale(1); opacity: 0.8; }
    50%  { transform: scale(1.6); opacity: 1; }
    100% { transform: scale(1); opacity: 0.8; }
}

/* ===== AI THINKING TEXT ===== */
.ai-thinking {
    font-size: 0.75rem;
    opacity: 0.75;
    animation: thinking 3s infinite;
}

@keyframes thinking {
    0% { opacity: 0.4; }
    50% { opacity: 1; }
    100% { opacity: 0.4; }
}

</style>

<div class="ai-hud">
    <div class="ai-core"></div>
    <div class="ai-title">AI DEFENSE CORE</div>
    <div class="ai-status">
        Neural Model: ONLINE<br>
        Threat Analysis: ACTIVE<br>
        Packet Integrity: VERIFIED
    </div>
    <div class="ai-thinking">
        ► Predicting intrusion vectors...
    </div>
</div>
""", unsafe_allow_html=True)












# =========================
# CRYPTO FUNCTIONS (BYTE SAFE)
# =========================
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_message(message, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    enc = cipher.encryptor()
    cipher_bytes = enc.update(message.encode()) + enc.finalize()
    return salt + iv + cipher_bytes   # 🔥 BYTES ONLY

def decrypt_message(data, password):
    salt, iv, cipher_text = data[:16], data[16:32], data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(cipher_text).decode()

# =========================
# STEGANOGRAPHY (BYTE SAFE + LENGTH BASED)
# =========================
def encode_image(image, secret_bytes):
    length = len(secret_bytes)
    binary = format(length, '032b') + ''.join(format(b, '08b') for b in secret_bytes)

    pixels = list(image.getdata())
    if len(binary) > len(pixels):
        raise ValueError("Image too small for this message")

    new_pixels = []
    i = 0
    for p in pixels:
        if i < len(binary):
            r = (p[0] & ~1) | int(binary[i])
            new_pixels.append((r, p[1], p[2]))
            i += 1
        else:
            new_pixels.append(p)

    img = Image.new(image.mode, image.size)
    img.putdata(new_pixels)
    return img

def decode_image(image):
    pixels = list(image.getdata())

    length_bits = ''.join(str(pixels[i][0] & 1) for i in range(32))
    length = int(length_bits, 2)

    data_bits = ''.join(str(pixels[i+32][0] & 1) for i in range(length * 8))
    return bytes(
        int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8)
    )

# =========================
# UI
# =========================
#st.title("🛡️ PROJECT KAVACH")
#st.markdown("`SYSTEM ONLINE • SECURE CHANNEL ACTIVE`")
#st.divider()
#st.title("🛡️ PROJECT KAVACH")
#st.markdown('<div class="typewriter">[ SYSTEM ONLINE • SECURE CHANNEL ACTIVE ]</div>',unsafe_allow_html=True)
#st.divider()
#tab1, tab2 = st.tabs(["🔒 ENCRYPT", "🔓 DECRYPT"])

# -------- ENCRYPT --------
with tab1:
    img = st.file_uploader("Upload Image", type=["png", "jpg"])
    msg = st.text_area("Secret Message")
    pwd = st.text_input("Password", type="password")

    if st.button("ENCRYPT & DOWNLOAD"):
        if img and msg and pwd:
            try:
                with st.spinner("Encrypting..."):
                    time.sleep(1)
                    encrypted_bytes = encrypt_message(msg, pwd)
                    image = Image.open(img).convert("RGB")
                    stego = encode_image(image, encrypted_bytes)
                    buf = io.BytesIO()
                    stego.save(buf, format="PNG")
                st.success("Encryption Successful")
                st.download_button("DOWNLOAD IMAGE", buf.getvalue(), "secure.png")
            except Exception as e:
                st.error(str(e))
        else:
            st.warning("Fill all fields")

# -------- DECRYPT --------
with tab2:
    img = st.file_uploader("Upload Secure Image", type=["png"], key="d")
    pwd = st.text_input("Password", type="password", key="p")

    if st.button("DECRYPT"):
        if img and pwd:
            try:
                with st.spinner("Decrypting..."):
                    time.sleep(1)
                    image = Image.open(img).convert("RGB")
                    hidden_bytes = decode_image(image)
                    text = decrypt_message(hidden_bytes, pwd)
                st.success("Message Recovered")
                st.code(text)
            except Exception:
                st.error("❌ Wrong password or corrupted image")
        else:
            st.warning("Upload image & password")










