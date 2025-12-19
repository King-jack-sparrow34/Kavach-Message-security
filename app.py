import streamlit as st
from PIL import Image
import io, os, time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import random

st.set_page_config(
    page_title="PROJECT KAVACH — CLASSIFIED",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
html, body, [class*="css"] {
    background-color: #020304;
    color: #7CFF00;
    font-family: 'Courier New', monospace;
}

.stApp {
    background: radial-gradient(circle at center, #0a0f12 0%, #020304 70%);
}

/* FULL SCREEN TERMINAL MODE */
.block-container {
    border: 1px solid rgba(124,255,0,0.3);
    border-radius: 18px;
    padding: 26px;
    box-shadow: 0 0 70px rgba(124,255,0,0.15);
    background: rgba(0,0,0,0.9);
}

/* SCANLINES */
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
        180deg,
        rgba(124,255,0,0.02) 0px,
        rgba(124,255,0,0.02) 1px,
        transparent 1px,
        transparent 6px
    );
    animation: scan 9s linear infinite;
    pointer-events: none;
    z-index: 0;
}

@keyframes scan {
    from { background-position: 0 0; }
    to { background-position: 0 100%; }
}

/* GLITCH TITLE */
@keyframes glitch {
    0% { text-shadow: 2px 0 #7CFF00; }
    25% { text-shadow: -2px 0 #FF0033; }
    50% { text-shadow: 2px 0 #00FFD5; }
    75% { text-shadow: -2px 0 #7CFF00; }
    100% { text-shadow: 2px 0 #FF0033; }
}

h1 {
    animation: glitch 1.6s infinite;
}

/* BOOT SCREEN */
.boot {
    text-align: center;
    padding-top: 120px;
    font-size: 18px;
}

/* AI CORE */
.core {
    width: 160px;
    height: 160px;
    border-radius: 50%;
    border: 2px solid #7CFF00;
    margin: auto;
    box-shadow: 0 0 70px #7CFF00;
    animation: pulse 2.8s infinite;
}

@keyframes pulse {
    0% { box-shadow: 0 0 25px #7CFF00; }
    50% { box-shadow: 0 0 110px #7CFF00; }
    100% { box-shadow: 0 0 25px #7CFF00; }
}

/* MAP DOTS */
.dot {
    fill: #ff0033;
    animation: blink 1.6s infinite;
}

@keyframes blink {
    0% { opacity: 0.3; r: 3; }
    50% { opacity: 1; r: 6; }
    100% { opacity: 0.3; r: 3; }
}
</style>
""", unsafe_allow_html=True)

# ======================
# BOOT SEQUENCE (MODE 6)
# ======================
boot = st.empty()
boot_lines = [
    "INITIALIZING AI CORE...",
    "LOADING QUANTUM MODULES...",
    "SECURE MEMORY VERIFIED",
    "GLOBAL SATELLITE LINK ESTABLISHED",
    "DEFENSE GRID ONLINE",
    "AI SENTIENCE CONFIRMED"
]

boot_text = ""
for line in boot_lines:
    boot_text += f"{line}\n"
    boot.markdown(f"<div class='boot'><pre>{boot_text}</pre></div>", unsafe_allow_html=True)
    time.sleep(0.5)

boot.empty()

# ======================
# MAIN UI
# ======================
st.title("🛡️ PROJECT KAVACH — COMMAND INTERFACE")
st.markdown("`CLASSIFICATION: TOP SECRET | AUTONOMOUS WAR AI ENABLED`")
st.divider()

left, center, right = st.columns([1.2, 1.6, 1.2])

# ======================
# AI TYPING ILLUSION (MODE 7)
# ======================
with left:
    st.subheader("🤖 AI INTERNAL DIALOGUE")
    ai_box = st.empty()
    ai_lines = [
        "Analyzing global network topology...",
        "Threat probability rising...",
        "Hostile intent confirmed.",
        "Deploying countermeasures.",
        "No human intervention required.",
        "Mission integrity preserved."
    ]

    ai_text = ""
    for l in ai_lines:
        for c in l:
            ai_text += c
            ai_box.code(ai_text)
            time.sleep(0.015)
        ai_text += "\n"
        time.sleep(0.3)

# ======================
# WORLD MAP + HEAT ZONES (MODE 8)
# ======================
with center:
    st.subheader("🌍 GLOBAL THREAT THEATRE")

    dots = ""
    heat = ""
    for _ in range(12):
        x = random.randint(60, 740)
        y = random.randint(60, 340)
        dots += f"<circle cx='{x}' cy='{y}' class='dot' />"
        heat += f"<circle cx='{x}' cy='{y}' r='30' fill='rgba(255,0,0,0.05)' />"

    st.markdown(f"""
    <svg viewBox="0 0 800 400" width="100%" height="380"
         style="border:1px solid rgba(124,255,0,0.35); border-radius:14px;">
        <rect width="100%" height="100%" fill="#020304"/>
        <text x="20" y="30" fill="#7CFF00" font-size="14">
            CYBER WAR ZONES — LIVE
        </text>
        {heat}
        {dots}
    </svg>
    """, unsafe_allow_html=True)

    st.markdown("<div class='core'></div>", unsafe_allow_html=True)
    st.markdown("**AI CORE STATUS:** ACTIVE")

# ======================
# FULL TERMINAL / STATS (MODE 9)
# ======================
with right:
    st.subheader("🪖 COMMAND STATUS")
    st.metric("Active Attacks", "193", "+27")
    st.metric("Neutralized", "4,882", "+311")
    st.metric("AI Autonomy", "100%")
    st.metric("Global Alert", "DEFCON 1")

st.divider()

tab1, tab2 = st.tabs(["🔒 ENCRYPT OPERATIONS", "🔓 DECRYPT OPERATIONS"])

with tab1:
    st.text_area("SECURE INPUT", height=160, key="encrypt_input")
    st.button("EXECUTE ENCRYPTION", key="encrypt_btn")

with tab2:
    st.text_area("ENCRYPTED PAYLOAD", height=160, key="decrypt_input")
    st.button("EXECUTE DECRYPTION", key="decrypt_btn")


st.markdown("`AI SENTIENCE LOCKED | HUMAN OVERRIDE DISABLED`")

with center:
    st.subheader("🌍 GLOBAL THREAT THEATRE")

    dots = ""
    heat = ""
    for _ in range(12):
        x = random.randint(60, 740)
        y = random.randint(60, 340)
        dots += f"<circle cx='{x}' cy='{y}' class='dot' />"
        heat += f"<circle cx='{x}' cy='{y}' r='30' fill='rgba(255,0,0,0.05)' />"

    st.markdown(f"""
    <svg viewBox="0 0 800 400" width="100%" height="380"
         style="border:1px solid rgba(124,255,0,0.35); border-radius:14px;">
        <rect width="100%" height="100%" fill="#020304"/>
        <text x="20" y="30" fill="#7CFF00" font-size="14">
            CYBER WAR ZONES — LIVE
        </text>
        {heat}
        {dots}
    </svg>
    """, unsafe_allow_html=True)

    st.markdown("<div class='core'></div>", unsafe_allow_html=True)
    st.markdown("**AI CORE STATUS:** ACTIVE")

# ======================
# FULL TERMINAL / STATS (MODE 9)
# ======================
with right:
    st.subheader("🪖 COMMAND STATUS")
    st.metric("Active Attacks", "193", "+27")
    st.metric("Neutralized", "4,882", "+311")
    st.metric("AI Autonomy", "100%")
    st.metric("Global Alert", "DEFCON 1")

st.divider()

tab1, tab2 = st.tabs(["🔒 ENCRYPT OPERATIONS", "🔓 DECRYPT OPERATIONS"])

with tab1:
    st.text_area("SECURE INPUT", height=160, key="encrypt_input")
    st.button("EXECUTE ENCRYPTION", key="encrypt_btn")

with tab2:
    st.text_area("ENCRYPTED PAYLOAD", height=160, key="decrypt_input")
    st.button("EXECUTE DECRYPTION", key="decrypt_btn")


st.markdown("`AI SENTIENCE LOCKED | HUMAN OVERRIDE DISABLED`")







































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















