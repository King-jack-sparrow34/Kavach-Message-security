import streamlit as st
from PIL import Image
import io, os, time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# =========================
# PAGE CONFIG (MUST BE FIRST)
# =========================
st.set_page_config(
    page_title="Project KAVACH",
    page_icon="🛡️",
    layout="wide"
)

# =========================
# HOLLYWOOD CYBER UI
# =========================
st.markdown("""
<style>

/* ===== CINEMATIC COLOR SYSTEM ===== */
:root {
    --neon: #00ffb3;
    --dark: #000402;
    --panel: rgba(0, 12, 9, 0.94);
    --line: rgba(0,255,179,0.35);
    --glow: rgba(0,255,179,0.22);
}

/* ===== BASE ===== */
.stApp {
    background:
        radial-gradient(1200px circle at top, #02231a, #000);
    color: var(--neon);
    font-family: "JetBrains Mono", Consolas, monospace;
}

/* ===== CRT CURVATURE ===== */
.stApp {
    transform: perspective(1200px) translateZ(0);
}

/* ===== FILM GRAIN ===== */
.stApp::after {
    content: "";
    position: fixed;
    inset: 0;
    background-image: url("https://grainy-gradients.vercel.app/noise.svg");
    opacity: 0.035;
    pointer-events: none;
    z-index: 1;
}

/* ===== HORIZONTAL SIGNAL SCAN ===== */
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background: linear-gradient(
        to bottom,
        transparent 0%,
        rgba(0,255,179,0.08) 50%,
        transparent 100%
    );
    animation: scanBeam 7s linear infinite;
    pointer-events: none;
    z-index: 1;
}

@keyframes scanBeam {
    from { transform: translateY(-120%); }
    to { transform: translateY(120%); }
}

/* ===== MAIN PANEL ===== */
.block-container {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 20px;
    padding: 34px;
    box-shadow:
        0 0 35px var(--glow),
        inset 0 0 30px rgba(0,255,179,0.06);
    position: relative;
    z-index: 2;
}

/* ===== BOOT SEQUENCE TEXT ===== */
.boot {
    font-size: 0.9rem;
    opacity: 0.85;
    line-height: 1.6;
    animation: bootGlow 2.5s ease-in-out infinite alternate;
}

@keyframes bootGlow {
    from { text-shadow: 0 0 4px var(--neon); }
    to { text-shadow: 0 0 10px var(--neon); }
}

/* ===== HEADER (EVENT GLITCH) ===== */
@keyframes cinematicGlitch {
    0% { text-shadow: 0 0 8px var(--neon); }
    48% { text-shadow: 0 0 8px var(--neon); }
    49% { text-shadow: -2px 0 #00ffd5, 2px 0 #00cc99; }
    50% { text-shadow: 0 0 10px var(--neon); }
    100% { text-shadow: 0 0 8px var(--neon); }
}

h1 {
    animation: cinematicGlitch 12s infinite;
    letter-spacing: 3px;
}

/* ===== TYPEWRITER STATUS ===== */
.typewriter {
    white-space: nowrap;
    overflow: hidden;
    border-right: 2px solid var(--neon);
    width: 0;
    animation:
        typing 3.5s steps(44, end) forwards,
        blink 0.8s infinite;
}

@keyframes typing {
    to { width: 100%; }
}

@keyframes blink {
    50% { border-color: transparent; }
}

/* ===== INPUT TERMINAL ===== */
.stTextInput input,
.stTextArea textarea {
    background: rgba(0,0,0,0.7);
    color: var(--neon);
    border: 1px solid var(--line);
    border-radius: 14px;
    box-shadow: inset 0 0 14px rgba(0,255,179,0.1);
}

/* ===== TACTICAL BUTTONS ===== */
.stButton > button {
    background: transparent;
    color: var(--neon);
    border: 1.6px solid var(--neon);
    border-radius: 14px;
    font-weight: 700;
    letter-spacing: 1.2px;
    transition: all 0.25s ease;
}

.stButton > button:hover {
    background: var(--neon);
    color: #00110b;
    box-shadow: 0 0 30px var(--neon);
    transform: translateY(-1px);
}

/* ===== TABS ===== */
.stTabs [data-baseweb="tab"] {
    background: rgba(0,0,0,0.55);
    border: 1px solid var(--line);
    border-radius: 12px;
    color: var(--neon);
}

.stTabs [aria-selected="true"] {
    background: var(--neon) !important;
    color: #00110b !important;
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

st.markdown("""
<div class="boot">
[ BOOT SEQUENCE INITIALIZED ]<br>
→ Loading cryptographic modules<br>
→ Verifying entropy sources<br>
→ Secure enclave established<br>
→ Defense matrix: <b>ONLINE</b>
</div>
""", unsafe_allow_html=True)

st.markdown(
    '<div class="typewriter">[ SYSTEM ONLINE • SECURE CHANNEL ACTIVE ]</div>',
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





