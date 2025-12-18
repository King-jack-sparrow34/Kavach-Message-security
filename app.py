import streamlit as st
from PIL import Image
import io, os, time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import random

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="Project KAVACH",
    page_icon="🛡️",
    layout="wide"
)

# =========================
# ULTRA MODE CYBER UI
# =========================
st.markdown("""
<style>
:root {
    --neon: #00ffb3;
    --danger: #ff003c;
    --panel: rgba(0, 10, 8, 0.96);
    --line: rgba(0,255,179,0.35);
}

/* BASE */
.stApp {
    background: radial-gradient(circle at top, #02231a, #000);
    color: var(--neon);
    font-family: "JetBrains Mono", Consolas, monospace;
}

/* BOOT OVERLAY */
#boot {
    position: fixed;
    inset: 0;
    background: black;
    z-index: 9999;
    display: flex;
    align-items: center;
    justify-content: center;
    animation: fade 6s forwards;
}
@keyframes fade {
    0%,80% {opacity:1}
    100% {opacity:0;visibility:hidden}
}

/* MATRIX */
.matrix {
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
        to bottom,
        rgba(0,255,179,0.1) 0px,
        rgba(0,255,179,0.1) 1px,
        transparent 1px,
        transparent 3px
    );
    animation: matrix 18s linear infinite;
    opacity: .08;
    pointer-events: none;
}
@keyframes matrix {
    from {background-position-y:0}
    to {background-position-y:100%}
}

/* HUD GRID */
.hud {
    position: fixed;
    inset: 0;
    background:
      linear-gradient(rgba(0,255,179,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,179,0.04) 1px, transparent 1px);
    background-size: 60px 60px;
    pointer-events: none;
}

/* SCAN */
.stApp::before {
    content:"";
    position: fixed;
    inset:0;
    background: linear-gradient(transparent, rgba(0,255,179,.08), transparent);
    animation: scan 7s linear infinite;
    pointer-events:none;
}
@keyframes scan {
    from {transform:translateY(-120%)}
    to {transform:translateY(120%)}
}

/* PANEL */
.block-container {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 18px;
    padding: 36px;
    box-shadow: 0 0 45px rgba(0,255,179,.2);
    position: relative;
    z-index: 3;
}

/* THREAT BAR */
.threat {
    height: 6px;
    width: 100%;
    background: linear-gradient(
        90deg,
        #00ffb3,
        #ffe600,
        var(--danger)
    );
    animation: threatPulse 2s infinite;
}
@keyframes threatPulse {
    0% {filter:brightness(1)}
    50% {filter:brightness(1.6)}
    100% {filter:brightness(1)}
}

/* ALERT FLASH */
.alert {
    animation: alertFlash .8s infinite;
}
@keyframes alertFlash {
    0% {box-shadow: 0 0 10px var(--danger)}
    50% {box-shadow: 0 0 35px var(--danger)}
    100% {box-shadow: 0 0 10px var(--danger)}
}

/* TEXT */
h1 {
    letter-spacing: 3px;
    animation: glitch 12s infinite;
}
@keyframes glitch {
    0%,96% {text-shadow:0 0 8px var(--neon)}
    97% {text-shadow:-2px 0 #00ffd5,2px 0 #00cc99}
    100% {text-shadow:0 0 8px var(--neon)}
}
</style>

<div id="boot">
  <div>
    [ KAVACH CORE BOOT ]<br>
    Loading crypto engine...<br>
    Establishing secure tunnel...<br>
    AI defense grid online...
  </div>
</div>

<div class="matrix"></div>
<div class="hud"></div>
""", unsafe_allow_html=True)

# =========================
# HEADER
# =========================
st.title("🛡️ PROJECT KAVACH")
st.markdown("### [ SYSTEM ONLINE • DEFENSE MATRIX ACTIVE ]")

# =========================
# THREAT LEVEL
# =========================
st.markdown("#### ⚠️ THREAT LEVEL")
st.markdown('<div class="threat"></div>', unsafe_allow_html=True)

# =========================
# LIVE TERMINAL LOGS
# =========================
st.markdown("#### 📡 LIVE SECURITY FEED")

log_box = st.empty()
logs = []

for _ in range(8):
    logs.append(
        f"[{time.strftime('%H:%M:%S')}] "
        f"NODE-{random.randint(10,99)} :: "
        f"{random.choice(['SCAN OK','INTRUSION BLOCKED','ENCRYPTION VERIFIED','PACKET DROPPED'])}"
    )
    log_box.code("\n".join(logs[-8:]), language="bash")
    time.sleep(0.2)

st.divider()

# =========================
# TABS
# =========================
tab1, tab2 = st.tabs(["🔒 ENCRYPT", "🔓 DECRYPT"])

with tab1:
    st.text_area("INPUT DATA")
    st.button("INITIATE ENCRYPTION")

with tab2:
    st.text_area("ENCRYPTED PAYLOAD")
    st.button("INITIATE DECRYPTION")

















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








