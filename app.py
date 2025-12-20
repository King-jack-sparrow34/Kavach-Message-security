import streamlit as st
from PIL import Image
import io, os, time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# =========================
# PAGE CONFIG (FIRST LINE)
# =========================
st.set_page_config(
    page_title="Project KAVACH",
    page_icon="🛡️",
    layout="wide"
)

# =========================
# ADVANCED CYBER UI (PRO)
# =========================
st.markdown("""
<style>

/* ===== ROOT COLORS ===== */
:root {
    --neon: #00ff9c;
    --bg: #020806;
    --panel: rgba(0, 10, 8, 0.92);
    --border: rgba(0,255,156,0.45);
    --glow: rgba(0,255,156,0.25);
}

/* ===== BASE APP ===== */
.stApp {
    background: radial-gradient(circle at top, #02130c, #000);
    color: var(--neon);
    font-family: "JetBrains Mono", "Courier New", monospace;
}

/* ===== CRT NOISE ===== */
.stApp::after {
    content: "";
    position: fixed;
    inset: 0;
    background-image: url("https://grainy-gradients.vercel.app/noise.svg");
    opacity: 0.04;
    pointer-events: none;
    z-index: 0;
}

/* ===== SCAN SWEEP ===== */
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background: linear-gradient(
        to bottom,
        transparent 0%,
        rgba(0,255,156,0.06) 50%,
        transparent 100%
    );
    animation: sweep 6s linear infinite;
    pointer-events: none;
    z-index: 0;
}

@keyframes sweep {
    from { transform: translateY(-100%); }
    to { transform: translateY(100%); }
}

/* ===== MAIN PANEL ===== */
.block-container {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 32px;
    box-shadow:
        0 0 30px var(--glow),
        inset 0 0 25px rgba(0,255,156,0.05);
    position: relative;
    z-index: 1;
}

/* ===== HEADER GLITCH (SUBTLE) ===== */
@keyframes glitch {
    0% { text-shadow: 0 0 6px var(--neon); }
    50% { text-shadow: -1px 0 #00ffaa, 1px 0 #00cc88; }
    100% { text-shadow: 0 0 6px var(--neon); }
}

h1 {
    animation: glitch 4s infinite;
    letter-spacing: 2px;
}

/* ===== TERMINAL TYPE LINE ===== */
.typewriter {
    font-size: 0.95rem;
    opacity: 0.85;
    white-space: nowrap;
    overflow: hidden;
    border-right: 2px solid var(--neon);
    width: 0;
    animation:
        typing 4s steps(48, end) forwards,
        blink 0.8s step-end infinite;
}

@keyframes typing {
    to { width: 100%; }
}

@keyframes blink {
    50% { border-color: transparent; }
}

/* ===== INPUTS ===== */
.stTextInput input,
.stTextArea textarea {
    background: rgba(0,0,0,0.6);
    color: var(--neon);
    border: 1px solid var(--border);
    border-radius: 12px;
    box-shadow: inset 0 0 12px rgba(0,255,156,0.08);
}

/* ===== BUTTONS ===== */
.stButton > button {
    background: transparent;
    color: var(--neon);
    border: 1.5px solid var(--neon);
    border-radius: 14px;
    font-weight: 600;
    letter-spacing: 1px;
    transition: all 0.25s ease;
}

.stButton > button:hover {
    background: var(--neon);
    color: #000;
    box-shadow: 0 0 25px var(--neon);
    transform: translateY(-1px);
}

/* ===== TABS ===== */
.stTabs [data-baseweb="tab"] {
    background: rgba(0,0,0,0.55);
    border: 1px solid var(--border);
    border-radius: 12px;
    color: var(--neon);
}

.stTabs [aria-selected="true"] {
    background: var(--neon) !important;
    color: #000 !important;
}

/* ===== DIVIDER ===== */
hr {
    border: none;
    height: 1px;
    background: linear-gradient(
        to right,
        transparent,
        var(--neon),
        transparent
    );
}

</style>
""", unsafe_allow_html=True)

# =========================
# UI CONTENT
# =========================
st.title("🛡️ PROJECT KAVACH")
st.markdown("`SYSTEM ONLINE • SECURE CHANNEL ACTIVE`")
st.divider()
st.title("🛡️ PROJECT KAVACH")
st.markdown('<div class="typewriter">[ SYSTEM ONLINE • SECURE CHANNEL ACTIVE ]</div>',unsafe_allow_html=True)
st.divider()
tab1, tab2 = st.tabs(["🔒 ENCRYPT", "🔓 DECRYPT"])

























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


















