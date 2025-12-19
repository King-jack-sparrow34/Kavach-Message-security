import streamlit as st
from PIL import Image
import io, os, time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import math

st.set_page_config(
    page_title="PROJECT KAVACH — GOD MODE",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
html, body, [class*="css"] {
    background-color: #000000;
    color: #00ffcc;
    font-family: 'Courier New', monospace;
}

.stApp {
    background: radial-gradient(circle at center, #001010 0%, #000000 60%);
}

/* SCANLINES */
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
        180deg,
        rgba(0,255,204,0.03) 0px,
        rgba(0,255,204,0.03) 1px,
        transparent 1px,
        transparent 4px
    );
    animation: scan 6s linear infinite;
    pointer-events: none;
    z-index: 0;
}

@keyframes scan {
    from { background-position: 0 0; }
    to { background-position: 0 100%; }
}

/* HUD PANEL */
.block-container {
    border: 1px solid #00ffcc;
    border-radius: 20px;
    padding: 25px;
    box-shadow: 0 0 40px rgba(0,255,204,0.2);
    background: rgba(0,0,0,0.85);
}

/* GLITCH TITLE */
@keyframes glitch {
    0% { text-shadow: 2px 0 #00ffcc; }
    25% { text-shadow: -2px 0 #ff0055; }
    50% { text-shadow: 2px 0 #00ffff; }
    75% { text-shadow: -2px 0 #00ffcc; }
    100% { text-shadow: 2px 0 #ff0055; }
}

h1 {
    animation: glitch 1.4s infinite;
}

/* TERMINAL TEXT */
.terminal {
    background: rgba(0,0,0,0.7);
    border: 1px solid #00ffcc;
    border-radius: 12px;
    padding: 15px;
    height: 300px;
    overflow: hidden;
}

/* PULSE CORE */
.core {
    width: 180px;
    height: 180px;
    border-radius: 50%;
    border: 2px solid #00ffcc;
    margin: auto;
    box-shadow: 0 0 40px #00ffcc;
    animation: pulse 2.5s infinite;
}

@keyframes pulse {
    0% { box-shadow: 0 0 20px #00ffcc; }
    50% { box-shadow: 0 0 80px #00ffcc; }
    100% { box-shadow: 0 0 20px #00ffcc; }
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ PROJECT KAVACH — AI COMMAND CORE")

st.markdown("`SYSTEM STATUS: FULL AI SENTIENCE | GOD MODE ENABLED`")
st.divider()

left, center, right = st.columns([1.2, 1, 1.2])

with left:
    st.subheader("🌐 GLOBAL THREAT FEED")
    terminal = st.empty()
    logs = [
        "Initializing neural lattice...",
        "Quantum encryption online",
        "Satellite uplink secured",
        "Foreign intrusion detected",
        "Counter-AI deployed",
        "Threat neutralized",
        "System stable"
    ]

    text = ""
    for log in logs:
        text += f"> {log}\n"
        terminal.markdown(f"<div class='terminal'>{text}</div>", unsafe_allow_html=True)
        time.sleep(0.4)

with center:
    st.subheader("🧠 AI NEURAL CORE")
    st.markdown("<div class='core'></div>", unsafe_allow_html=True)
    st.markdown("**CONSCIOUSNESS LEVEL:** 100%")
    st.markdown("**DECISION LATENCY:** 0.002ms")

with right:
    st.subheader("📡 LIVE METRICS")
    st.metric("Threats Tracked", "128", "+12")
    st.metric("Systems Protected", "9,842", "+221")
    st.metric("Encryption Depth", "AES-512")
    st.metric("AI Autonomy", "MAX")

st.divider()

tab1, tab2 = st.tabs(["🔒 ENCRYPT", "🔓 DECRYPT"])

with tab1:
    st.text_area("INPUT DATA", height=150)
    st.button("EXECUTE ENCRYPTION")

with tab2:
    st.text_area("SECURE PAYLOAD", height=150)
    st.button("EXECUTE DECRYPTION")








































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












