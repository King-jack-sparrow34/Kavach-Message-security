import streamlit as st
from PIL import Image
import io, base64, os, time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="Project KAVACH",
    page_icon="🛡️",
    layout="wide"
)

# =========================
# FINAL CYBER UI + GLITCH
# =========================
st.markdown("""
<style>

/* BASE */
.stApp {
    background-color: #000;
    color: #00ff00;
    font-family: "Courier New", monospace;
}

/* SCANLINES */
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
        180deg,
        rgba(0,255,0,0.04) 0px,
        rgba(0,255,0,0.04) 1px,
        transparent 1px,
        transparent 3px
    );
    animation: scan 3.5s linear infinite;
    pointer-events: none;
    z-index: 0;
}

@keyframes scan {
    from { background-position: 0 0; }
    to { background-position: 0 100%; }
}

/* PANEL */
.block-container {
    position: relative;
    z-index: 1;
    background: rgba(0,0,0,0.88);
    border: 1px solid #00ff00;
    border-radius: 16px;
    padding: 30px;
    box-shadow: 0 0 25px rgba(0,255,0,0.15);
}

/* GLITCH TEXT */
@keyframes glitch {
    0% { text-shadow: 2px 0 #00ff00; }
    25% { text-shadow: -2px 0 #ff0055; }
    50% { text-shadow: 2px 0 #00ffff; }
    75% { text-shadow: -2px 0 #00ff00; }
    100% { text-shadow: 2px 0 #ff0055; }
}

h1, h2, h3 {
    animation: glitch 1.3s infinite;
}

/* TYPE EFFECT */
.typewriter {
    white-space: nowrap;
    overflow: hidden;
    border-right: 2px solid #00ff00;
    width: 0;
    animation: typing 4s steps(40, end) infinite alternate,
               blink 0.7s infinite;
}

@keyframes typing {
    from { width: 0; }
    to { width: 100%; }
}

@keyframes blink {
    50% { border-color: transparent; }
}

/* INPUTS */
.stTextInput input,
.stTextArea textarea,
.stFileUploader {
    background: rgba(0,0,0,0.7);
    color: #00ff00;
    border: 1px solid #00ff00;
    border-radius: 10px;
}

/* BUTTONS */
.stButton > button {
    background: transparent;
    color: #00ff00;
    border: 2px solid #00ff00;
    border-radius: 12px;
    font-weight: bold;
    width: 100%;
    transition: 0.3s;
}

.stButton > button:hover {
    background: #00ff00;
    color: #000;
    box-shadow: 0 0 15px #00ff00;
    transform: scale(1.03);
}

/* TABS */
.stTabs [data-baseweb="tab"] {
    background: rgba(0,0,0,0.6);
    border: 1px solid #00ff00;
    border-radius: 10px;
    color: #00ff00;
}

.stTabs [aria-selected="true"] {
    background: #00ff00 !important;
    color: #000 !important;
}

</style>
""", unsafe_allow_html=True)

# =========================
# CRYPTO FUNCTIONS
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
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted).decode()

def decrypt_message(enc, password):
    data = base64.b64decode(enc)
    salt, iv, cipher_text = data[:16], data[16:32], data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cipher_text) + decryptor.finalize()

# =========================
# STEGANOGRAPHY
# =========================
def encode_image(image, text):
    binary = ''.join(format(ord(c), '08b') for c in text) + '1111111111111110'
    pixels = list(image.getdata())
    new_pixels = []
    idx = 0

    for pixel in pixels:
        if idx < len(binary):
            r = (pixel[0] & ~1) | int(binary[idx])
            new_pixels.append((r, pixel[1], pixel[2]))
            idx += 1
        else:
            new_pixels.append(pixel)

    img = Image.new(image.mode, image.size)
    img.putdata(new_pixels)
    return img

def decode_image(image):
    bits = ""
    for pixel in image.getdata():
        bits += str(pixel[0] & 1)

    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    msg = ""
    for c in chars:
        if c == "11111110":
            break
        msg += chr(int(c, 2))
    return msg

# =========================
# UI
# =========================
st.title("🛡️ PROJECT KAVACH")
st.markdown('<div class="typewriter">[ SYSTEM ONLINE • SECURE CHANNEL ACTIVE ]</div>', unsafe_allow_html=True)
st.divider()

tab1, tab2 = st.tabs(["🔒 ENCRYPT", "🔓 DECRYPT"])

with tab1:
    img = st.file_uploader("Upload Image", type=["png", "jpg"])
    msg = st.text_area("Secret Message")
    pwd = st.text_input("Password", type="password")

    if st.button("ENCRYPT & DOWNLOAD"):
        if img and msg and pwd:
            with st.spinner("Encrypting..."):
                time.sleep(1)
                encrypted = encrypt_message(msg, pwd)
                image = Image.open(img).convert("RGB")
                stego = encode_image(image, encrypted)
                buf = io.BytesIO()
                stego.save(buf, format="PNG")
            st.success("Encryption Successful")
            st.download_button("DOWNLOAD IMAGE", buf.getvalue(), "secure.png")
        else:
            st.warning("Fill all fields")

with tab2:
    img = st.file_uploader("Upload Secure Image", type=["png"], key="d")
    pwd = st.text_input("Password", type="password", key="p")

    if st.button("DECRYPT"):
        if img and pwd:
            try:
                with st.spinner("Decrypting..."):
                    time.sleep(1)
                    image = Image.open(img).convert("RGB")
                    hidden = decode_image(image)
                    text = decrypt_message(hidden, pwd)
                st.success("Message Recovered")
                st.code(text.decode())
            except:
                st.error("Wrong password or corrupted image")
        else:
            st.warning("Upload image & password")

