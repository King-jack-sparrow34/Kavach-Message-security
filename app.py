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
    page_title="PROJECT KAVACH — DARK OPS",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
html, body, [class*="css"] {
    background-color: #050608;
    color: #7CFF00;
    font-family: 'Courier New', monospace;
}

.stApp {
    background: radial-gradient(circle at center, #0a0f12 0%, #050608 65%);
}

/* SCANLINES */
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
        180deg,
        rgba(124,255,0,0.025) 0px,
        rgba(124,255,0,0.025) 1px,
        transparent 1px,
        transparent 5px
    );
    animation: scan 8s linear infinite;
    pointer-events: none;
    z-index: 0;
}

@keyframes scan {
    from { background-position: 0 0; }
    to { background-position: 0 100%; }
}

/* COMMAND PANEL */
.block-container {
    background: rgba(0,0,0,0.82);
    border: 1px solid rgba(124,255,0,0.35);
    border-radius: 18px;
    padding: 28px;
    box-shadow: 0 0 60px rgba(124,255,0,0.12);
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

/* RADAR DOT */
.dot {
    fill: #ff0033;
    animation: pulse 1.8s infinite;
}

@keyframes pulse {
    0% { r: 3; opacity: 0.4; }
    50% { r: 6; opacity: 1; }
    100% { r: 3; opacity: 0.4; }
}

/* STATUS TEXT */
.status {
    color: #7CFF00;
    font-size: 14px;
    opacity: 0.85;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ PROJECT KAVACH — DARK OPS COMMAND")

st.markdown("`CLASSIFICATION: TOP SECRET | AUTONOMOUS AI WAR MODE`")
st.divider()

left, center, right = st.columns([1.2, 1.6, 1.2])

with left:
    st.subheader("📡 THREAT LOG")
    log_box = st.empty()
    logs = [
        "Initializing global sensors",
        "Establishing satellite lock",
        "Foreign signal triangulated",
        "Zero-day exploit detected",
        "Counter-measure deployed",
        "Hostile node neutralized",
        "Network integrity restored"
    ]

    output = ""
    for l in logs:
        output += f"> {l}\n"
        log_box.code(output)
        time.sleep(0.35)

with center:
    st.subheader("🌍 GLOBAL CYBER ATTACK MAP")

    attacks = ""
    for _ in range(8):
        x = random.randint(40, 760)
        y = random.randint(40, 360)
        attacks += f"<circle cx='{x}' cy='{y}' class='dot' />"

    st.markdown(f"""
    <svg viewBox="0 0 800 400" width="100%" height="380"
         style="border:1px solid rgba(124,255,0,0.3); border-radius:14px;">
        <rect width="100%" height="100%" fill="#030405"/>
        <text x="20" y="30" fill="#7CFF00" font-size="14">LIVE CYBER THEATRE</text>
        {attacks}
    </svg>
    """, unsafe_allow_html=True)

with right:
    st.subheader("🪖 MILITARY STATUS")
    st.metric("Active Threats", "147", "+19")
    st.metric("Defense Nodes", "12,481", "+402")
    st.metric("AI Autonomy", "100%")
    st.metric("Alert Level", "DEFCON 1")

st.divider()

tab1, tab2 = st.tabs(["🔒 ENCRYPT OPS", "🔓 DECRYPT OPS"])

with tab1:
    st.text_area("PLAINTEXT INPUT", height=160)
    st.button("EXECUTE MILITARY ENCRYPTION")

with tab2:
    st.text_area("ENCRYPTED PAYLOAD", height=160)
    st.button("EXECUTE MILITARY DECRYPTION")

st.markdown("<div class='status'>AI CORE STATUS: STABLE | SENTIENCE LOCKED</div>", unsafe_allow_html=True)






























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
















