import streamlit as st
from PIL import Image
import io, os, time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
# =========================
# AI SENTIENCE ENGINE
# =========================
import random
import time

# AI STATES
AI_STATES = {
    "IDLE": {
        "color": "#00ffb3",
        "msg": "System stable. Monitoring background noise."
    },
    "ANALYZING": {
        "color": "#00e5ff",
        "msg": "Analyzing anomalous behavior patterns."
    },
    "ALERT": {
        "color": "#ff003c",
        "msg": "⚠️ Threat detected. Initiating countermeasures."
    },
    "SECURED": {
        "color": "#00ff6a",
        "msg": "Threat neutralized. System integrity restored."
    }
}

if "ai_state" not in st.session_state:
    st.session_state.ai_state = "IDLE"

# Random state transitions (cinematic illusion)
if random.random() > 0.75:
    st.session_state.ai_state = random.choice(list(AI_STATES.keys()))

state = st.session_state.ai_state
state_color = AI_STATES[state]["color"]
state_msg = AI_STATES[state]["msg"]

# =========================
# AI SENTIENCE HUD
# =========================
st.markdown(f"""
<style>

/* ===== AI HUD OVERRIDE ===== */
.ai-hud {{
    border: 1px solid {state_color};
    box-shadow:
        0 0 35px {state_color},
        inset 0 0 20px rgba(0,0,0,0.4);
}}

.ai-core {{
    background: {state_color};
    box-shadow: 0 0 25px {state_color};
    animation: pulse-{state} 1.6s infinite;
}}

@keyframes pulse-{state} {{
    0% {{ transform: scale(1); opacity: 0.8; }}
    50% {{ transform: scale(1.8); opacity: 1; }}
    100% {{ transform: scale(1); opacity: 0.8; }}
}}

.ai-thinking {{
    color: {state_color};
}}

</style>

<div class="ai-hud">
    <div class="ai-core"></div>
    <div class="ai-title">AI DEFENSE CORE</div>
    <div class="ai-status">
        State: <b>{state}</b><br>
        Neural Confidence: {random.randint(92,99)}%<br>
        Threat Index: {random.randint(1,7)}/10
    </div>
    <div class="ai-thinking">
        ► {state_msg}
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











