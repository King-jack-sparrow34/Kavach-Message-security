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
# CINEMATIC CYBER UI
# =========================
st.markdown("""
<style>

/* ===== COLOR SYSTEM ===== */
:root {
    --neon: #00ffb3;
    --dark: #000402;
    --panel: rgba(0, 12, 9, 0.95);
    --line: rgba(0,255,179,0.35);
    --glow: rgba(0,255,179,0.22);
}

/* ===== BASE ===== */
.stApp {
    background: radial-gradient(circle at top, #02231a, #000);
    color: var(--neon);
    font-family: "JetBrains Mono", Consolas, monospace;
}

/* ===== FULLSCREEN BOOT OVERLAY ===== */
#boot-screen {
    position: fixed;
    inset: 0;
    background: black;
    z-index: 9999;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-direction: column;
    animation: bootFade 6s forwards;
}

@keyframes bootFade {
    0% { opacity: 1; }
    80% { opacity: 1; }
    100% { opacity: 0; visibility: hidden; }
}

.boot-text {
    font-size: 1rem;
    line-height: 1.8;
    opacity: 0.9;
    text-shadow: 0 0 12px var(--neon);
}

/* ===== MATRIX RAIN ===== */
.matrix {
    position: fixed;
    inset: 0;
    background:
        repeating-linear-gradient(
            to bottom,
            rgba(0,255,179,0.08) 0px,
            rgba(0,255,179,0.08) 1px,
            transparent 1px,
            transparent 3px
        );
    animation: matrixMove 18s linear infinite;
    opacity: 0.08;
    pointer-events: none;
    z-index: 1;
}

@keyframes matrixMove {
    from { background-position-y: 0; }
    to { background-position-y: 100%; }
}

/* ===== HUD GRID ===== */
.hud {
    position: fixed;
    inset: 0;
    background:
        linear-gradient(rgba(0,255,179,0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,179,0.04) 1px, transparent 1px);
    background-size: 60px 60px;
    opacity: 0.35;
    pointer-events: none;
    z-index: 1;
}

/* ===== SCAN BEAM ===== */
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background: linear-gradient(
        to bottom,
        transparent,
        rgba(0,255,179,0.08),
        transparent
    );
    animation: scan 7s linear infinite;
    pointer-events: none;
    z-index: 2;
}

@keyframes scan {
    from { transform: translateY(-120%); }
    to { transform: translateY(120%); }
}

/* ===== PANEL ===== */
.block-container {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 20px;
    padding: 36px;
    box-shadow:
        0 0 40px var(--glow),
        inset 0 0 30px rgba(0,255,179,0.05);
    position: relative;
    z-index: 3;
}

/* ===== HEADER GLITCH (RARE) ===== */
@keyframes glitch {
    0%, 96%, 100% { text-shadow: 0 0 8px var(--neon); }
    97% { text-shadow: -2px 0 #00ffd5, 2px 0 #00cc99; }
}

h1 {
    animation: glitch 14s infinite;
    letter-spacing: 3px;
}

/* ===== TYPE LINE ===== */
.typewriter {
    white-space: nowrap;
    overflow: hidden;
    border-right: 2px solid var(--neon);
    width: 0;
    animation:
        typing 3.5s steps(40, end) forwards,
        blink 0.8s infinite;
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
    background: rgba(0,0,0,0.7);
    color: var(--neon);
    border: 1px solid var(--line);
    border-radius: 14px;
}

/* ===== BUTTONS ===== */
.stButton > button {
    background: transparent;
    color: var(--neon);
    border: 1.6px solid var(--neon);
    border-radius: 14px;
    font-weight: 700;
    letter-spacing: 1.1px;
    transition: 0.25s;
}

.stButton > button:hover {
    background: var(--neon);
    color: #00110b;
    box-shadow: 0 0 30px var(--neon);
    transform: translateY(-1px);
}

/* ===== TABS ===== */
.stTabs [data-baseweb="tab"] {
    background: rgba(0,0,0,0.6);
    border: 1px solid var(--line);
    border-radius: 12px;
    color: var(--neon);
}

.stTabs [aria-selected="true"] {
    background: var(--neon) !important;
    color: #00110b !important;
}

</style>

<!-- BOOT SCREEN -->
<div id="boot-screen">
  <div class="boot-text">
    [ INITIALIZING KAVACH CORE ]<br>
    → Loading cryptographic engine<br>
    → Verifying secure memory<br>
    → Establishing encrypted tunnel<br>
    → Threat surface: <b>MONITORED</b><br>
    → Defense grid: <b>ACTIVE</b>
  </div>
</div>

<div class="matrix"></div>
<div class="hud"></div>
""", unsafe_allow_html=True)

# =========================
# MAIN UI
# =========================
st.title("🛡️ PROJECT KAVACH")

st.markdown(
    '<div class="typewriter">[ SYSTEM ONLINE • MILITARY-GRADE ENCRYPTION ENABLED ]</div>',
    unsafe_allow_html=True
)

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






