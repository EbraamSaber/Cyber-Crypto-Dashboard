import streamlit as st
import pandas as pd
import plotly.express as px
import string
from datetime import datetime

# ==========================================
# 1. PAGE CONFIGURATION
# ==========================================
st.set_page_config(
    page_title="Project Cybersecurity",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
    <style>
    .stApp { background-color: #0e1117; }
    .main-title {
        font-size: 50px; font-weight: 900;
        background: linear-gradient(90deg, #00ff88, #00bdff);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        text-align: center; margin-bottom: 10px;
    }
    .academic-header {
        background-color: #161b22; padding: 20px; border-radius: 15px;
        border-left: 5px solid #00ff88; margin-bottom: 25px;
    }
    .student-card {
        background-color: #0d1117; border: 1px solid #30363d;
        padding: 10px; border-radius: 8px; text-align: center;
    }
    .hint-box {
        background-color: rgba(0, 255, 136, 0.1);
        border-left: 3px solid #00ff88;
        padding: 10px; margin-top: 5px;
        font-size: 13px; color: #00ff88; border-radius: 5px;
    }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 2. ACADEMIC HEADER
# ==========================================
st.markdown("<div class='main-title'>Project Cybersecurity</div>", unsafe_allow_html=True)

with st.container():
    st.markdown("<div class='academic-header'>", unsafe_allow_html=True)
    col_sup1, col_sup2 = st.columns(2)
    with col_sup1:
        st.markdown("### 👨‍🏫 Supervised By:")
        st.markdown("#### Prof.Dr. Mohamed Abdel Hamid")
    with col_sup2:
        st.markdown("### 👩‍💻 Teaching Assistants:")
        st.markdown("- Eng. EL-Shimaa Haroun\n- Eng. Sohila Abdallah")
    st.markdown("---")
    st.markdown("### 👥 Project Team Members:")
    st_cols = st.columns(5)
    students = [
        {"name": "Ebraam Saber Sedky",   "id": "231018097"},
        {"name": "Mina Saber Milad",      "id": "241008628"},
        {"name": "Mohamed Ali Saleh",     "id": "241009089"},
        {"name": "Abram Gergis Milad",    "id": "241008627"},
        {"name": "Mohamed Mustafa Adly",  "id": "241009155"},
    ]
    for i, col in enumerate(st_cols):
        with col:
            st.markdown(
                f"<div class='student-card'>"
                f"<p style='color:#00ff88; margin:0;'><b>{students[i]['name']}</b></p>"
                f"<p style='color:#8b949e; font-size:12px; margin:0;'>ID: {students[i]['id']}</p>"
                f"</div>",
                unsafe_allow_html=True,
            )
    st.markdown("</div>", unsafe_allow_html=True)

# ==========================================
# 3. COMMON UTILS
# ==========================================

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def power(base, expo, m):
    res = 1
    base %= m
    while expo > 0:
        if expo % 2 == 1:
            res = (res * base) % m
        base = (base * base) % m
        expo //= 2
    return res

# ==========================================
# 4. ALGORITHMS
# ==========================================

# ── RSA Key Generator ──────────────────────
def generate_rsa_keys_simple():
    return "17,3233", "2753,3233"

# ── 1. CAESAR ──────────────────────────────
def encrypt_caesar(text, n):
    try:
        n = int(n)
    except Exception:
        n = 0
    res = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            res += chr((ord(ch) - base + n) % 26 + base)
        else:
            res += ch
    return res

def decrypt_caesar(text, n):
    try:
        return encrypt_caesar(text, -int(n))
    except Exception:
        return encrypt_caesar(text, 0)

# ── 2. ROT13 ──────────────────────────────
def rot13_encrypt(text):
    res = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            res += chr((ord(ch) - base + 13) % 26 + base)
        else:
            res += ch
    return res

# ── 3. RAIL FENCE ─────────────────────────
def rail_fence_encode(text, n):
    try:
        n = int(n)
    except Exception:
        n = 3
    if n < 2:
        return text
    fence = [[] for _ in range(n)]
    rail, step = 0, 1
    for ch in text:
        fence[rail].append(ch)
        rail += step
        if rail == 0 or rail == n - 1:
            step *= -1
    return ''.join(''.join(r) for r in fence)

def rail_fence_decode(cipher, n):
    try:
        n = int(n)
    except Exception:
        n = 3
    if n < 2:
        return cipher
    pattern = list(range(n)) + list(range(n - 2, 0, -1))
    pos = [pattern[i % len(pattern)] for i in range(len(cipher))]
    res = [''] * len(cipher)
    idx = 0
    for r in range(n):
        for i in range(len(cipher)):
            if pos[i] == r:
                res[i] = cipher[idx]
                idx += 1
    return ''.join(res)

# ── 4. REVERSE ────────────────────────────
def reverse_cipher(text):
    return text[::-1]

# ── 5. RSA ────────────────────────────────
def rsa_process_smart(text, key_input, operation):
    try:
        exp, mod = map(int, key_input.split(","))
        is_numbers = all(part.isdigit() for part in text.split())
        if operation == "ENCRYPT":
            if is_numbers:
                nums = list(map(int, text.split()))
                return ' '.join(str(power(n, exp, mod)) for n in nums)
            else:
                return ' '.join(str(power(ord(c), exp, mod)) for c in text)
        else:
            nums = list(map(int, text.split()))
            result = []
            for n in nums:
                val = power(n, exp, mod)
                result.append(chr(val) if 32 <= val <= 126 else str(val))
            return ''.join(result)
    except Exception:
        return "Error: Check input format — key should be 'exp,mod' (e.g., 17,3233)"

# ── 6. COLUMNAR TRANSPOSITION ─────────────
def columnar_encrypt(text, key):
    try:
        col = len(key)
        row = -(-len(text) // col)
        matrix = [['' for _ in range(col)] for _ in range(row)]
        k = 0
        for i in range(row):
            for j in range(col):
                if k < len(text):
                    matrix[i][j] = text[k]
                    k += 1
        result = ""
        for num in sorted(key):
            idx = key.index(num)
            for i in range(row):
                result += matrix[i][idx]
        return result
    except Exception:
        return "Error: Transposition key must be numeric sequence (e.g., 312)"

def columnar_decrypt(ciphertext, key):
    try:
        keylen = len(key)
        length = len(ciphertext)
        tmp = {int(k): "" for k in key}
        for i in range(length):
            tmp[int(key[i % keylen])] += "x"
        column_sizes = {k: len(tmp[k]) for k in tmp}
        sorted_keys = sorted(tmp.keys())
        cipher_columns = {}
        start = 0
        for k in sorted_keys:
            cipher_columns[k] = ciphertext[start: start + column_sizes[k]]
            start += column_sizes[k]
        plaintext = ""
        for i in range(length):
            k = int(key[i % keylen])
            plaintext += cipher_columns[k][0]
            cipher_columns[k] = cipher_columns[k][1:]
        return plaintext
    except Exception:
        return "Error: Transposition key must be numeric sequence (e.g., 312)"

# ── 7. VIGENERE ───────────────────────────
def encrypt_vigenere(text, key):
    key = key.lower()
    res = ""
    j = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[j % len(key)]) - ord('a')
            base = ord('A') if ch.isupper() else ord('a')
            res += chr((ord(ch) - base + shift) % 26 + base)
            j += 1
        else:
            res += ch
    return res

def decrypt_vigenere(text, key):
    key = key.lower()
    res = ""
    j = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[j % len(key)]) - ord('a')
            base = ord('A') if ch.isupper() else ord('a')
            res += chr((ord(ch) - base - shift) % 26 + base)
            j += 1
        else:
            res += ch
    return res

# ── 8. XOR ────────────────────────────────
def xor_encrypt(text, key):
    if not key:
        return "Error: Key cannot be empty"
    return ' '.join(str(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

def xor_decrypt(cipher, key):
    try:
        if not key:
            return "Error: Key cannot be empty"
        nums = list(map(int, cipher.split()))
        return ''.join(chr(n ^ ord(key[i % len(key)])) for i, n in enumerate(nums))
    except Exception:
        return "Error: XOR decrypt expects space-separated numbers from encryption output"

def xor_image_process(image_bytes, key):
    if not key:
        return image_bytes
    return bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(image_bytes)])

# ── 9. AFFINE ─────────────────────────────
def affine_encrypt(text, key):
    try:
        a, b = map(int, key.split(','))
        if gcd(a, 26) != 1:
            return "Error: 'a' must be coprime with 26 (valid: 1,3,5,7,9,11,15,17,19,21,23,25)"
        res = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                res += chr((a * (ord(ch) - base) + b) % 26 + base)
            else:
                res += ch
        return res
    except Exception:
        return "Error: Affine key must be 'a,b' (e.g., 5,8)"

def affine_decrypt(text, key):
    try:
        a, b = map(int, key.split(','))
        if gcd(a, 26) != 1:
            return "Error: 'a' must be coprime with 26 (valid: 1,3,5,7,9,11,15,17,19,21,23,25)"
        a_inv = modinv(a, 26)
        res = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                res += chr((a_inv * (ord(ch) - base - b)) % 26 + base)
            else:
                res += ch
        return res
    except Exception:
        return "Error: Affine key must be 'a,b' (e.g., 5,8)"

# ── 10. ATBASH ────────────────────────────
def atbash_cipher(text):
    res = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            res += chr(base + 25 - (ord(ch) - base))
        else:
            res += ch
    return res

# ==========================================
# 5. UTILS
# ==========================================

HINTS = {
    "Caesar":        "💡 Hint: Use a single integer (e.g., 3).",
    "ROT13":         "💡 Hint: No key needed (fixed shift of 13).",
    "Rail Fence":    "💡 Hint: Enter number of rails (e.g., 3).",
    "Reverse":       "💡 Hint: No key needed (reverses the text).",
    "RSA":           "💡 Hint: Use 'e,n' for encrypt or 'd,n' for decrypt. Example: 17,3233",
    "Transposition": "💡 Hint: Use a numeric sequence (e.g., 312).",
    "Vigenere":      "💡 Hint: Use a word key (e.g., SECRET).",
    "XOR":           "💡 Hint: Use any string key. Decrypt expects numbers from encrypt output.",
    "Affine":        "💡 Hint: Use 'a,b' where a is coprime with 26 (e.g., 5,8).",
    "Atbash":        "💡 Hint: No key needed (A ↔ Z).",
}

def check_key_strength(key):
    if not key:
        return 0, "Empty", "#333"
    score = sum([
        len(key) >= 8,
        any(c.isdigit() for c in key),
        any(c in string.punctuation for c in key),
    ])
    colors = {0: "#777", 1: "#ff4b4b", 2: "#ffaa00", 3: "#00ff88"}
    labels = {0: "Too Short", 1: "Weak", 2: "Medium", 3: "Strong"}
    return score * 33.3, labels[score], colors[score]

# ==========================================
# 6. MAIN UI
# ==========================================

if 'history' not in st.session_state:
    st.session_state.history = []

tab_text, tab_img, tab_file = st.tabs(["🔤 Text Algorithms (10)", "🖼️ Image Encryption", "📁 File Encryption"])

# ── Text Tab ──────────────────────────────
with tab_text:
    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        st.subheader("📥 Input")
        msg = st.text_area("Message:", height=150)

        algo = st.selectbox(
            "Algorithm:",
            ["Caesar", "ROT13", "Rail Fence", "Reverse", "RSA",
             "Transposition", "Vigenere", "XOR", "Affine", "Atbash"],
        )
        st.markdown(f"<div class='hint-box'>{HINTS[algo]}</div>", unsafe_allow_html=True)

        if algo == "RSA":
            k_col1, k_col2 = st.columns([3, 1])
            with k_col2:
                if st.button("Gen RSA"):
                    pub, priv = generate_rsa_keys_simple()
                    st.session_state.gk = pub
                    st.info(f"Public: {pub} | Private: {priv}")
            with k_col1:
                key_val = st.text_input("Key / Params:", value=st.session_state.get('gk', ''))
            s_val, s_txt, s_clr = check_key_strength(key_val)
            st.markdown(f"Strength: <b style='color:{s_clr}'>{s_txt}</b>", unsafe_allow_html=True)
            st.progress(min(s_val / 100, 1.0))
        else:
            key_val = st.text_input("Key / Params:", value="")

        mode    = st.radio("Action:", ["Encrypt 🔒", "Decrypt 🔓"], horizontal=True)
        run_btn = st.button("🚀 EXECUTE")

    with col2:
        st.subheader("📤 Output")
        res_text = ""

        if run_btn and msg:
            is_enc = "Encrypt" in mode

            if   algo == "Caesar":        res_text = encrypt_caesar(msg, key_val)       if is_enc else decrypt_caesar(msg, key_val)
            elif algo == "ROT13":         res_text = rot13_encrypt(msg)
            elif algo == "Rail Fence":    res_text = rail_fence_encode(msg, key_val)    if is_enc else rail_fence_decode(msg, key_val)
            elif algo == "Reverse":       res_text = reverse_cipher(msg)
            elif algo == "RSA":           res_text = rsa_process_smart(msg, key_val, "ENCRYPT" if is_enc else "DECRYPT")
            elif algo == "Transposition": res_text = columnar_encrypt(msg, key_val)     if is_enc else columnar_decrypt(msg, key_val)
            elif algo == "Vigenere":      res_text = encrypt_vigenere(msg, key_val)     if is_enc else decrypt_vigenere(msg, key_val)
            elif algo == "XOR":           res_text = xor_encrypt(msg, key_val)          if is_enc else xor_decrypt(msg, key_val)
            elif algo == "Affine":        res_text = affine_encrypt(msg, key_val)       if is_enc else affine_decrypt(msg, key_val)
            elif algo == "Atbash":        res_text = atbash_cipher(msg)

            st.session_state.history.append({
                "Time":   datetime.now().strftime("%H:%M"),
                "Algo":   algo,
                "Action": mode,
            })

            st.text_area("Result:", value=res_text, height=150)

            if res_text:
                st.markdown("### 📊 Frequency Analysis")
                char_counts = pd.Series(list(res_text)).value_counts().reset_index().head(10)
                char_counts.columns = ['Char', 'Count']
                st.plotly_chart(
                    px.bar(char_counts, x='Char', y='Count', template="plotly_dark", height=300),
                    use_container_width=True,
                )

# ── Image Tab ─────────────────────────────
with tab_img:
    st.subheader("📷 Image Pixel Encryption")
    img_file = st.file_uploader("Upload Image or Encrypted File", type=["jpg", "png", "jpeg", "bin"])
    img_key  = st.text_input("Image Encryption Key:", type="password", key="img_k")

    if img_file and img_key:
        if st.button("🔐 Process (Encrypt / Decrypt)"):
            file_bytes     = img_file.read()
            processed_data = xor_image_process(file_bytes, img_key)
            out_name = (
                "decrypted_image.jpg" if img_file.name.endswith(".bin")
                else "encrypted_image.bin"
            )
            st.success("Process Completed!")
            st.download_button(
                label="📥 Download Result",
                data=processed_data,
                file_name=out_name,
                mime="application/octet-stream",
            )

# ── File Tab ──────────────────────────────
with tab_file:
    st.subheader("📁 File Encryption / Decryption")
    st.markdown("Upload any `.txt` file, choose an algorithm, and download the result.")

    uploaded_file = st.file_uploader("Upload Text File (.txt)", type=["txt"], key="file_upload")

    f_col1, f_col2 = st.columns([1, 1], gap="large")

    with f_col1:
        f_algo = st.selectbox(
            "Algorithm:",
            ["Caesar", "ROT13", "Rail Fence", "Reverse", "RSA",
             "Transposition", "Vigenere", "XOR", "Affine", "Atbash"],
            key="f_algo",
        )
        st.markdown(f"<div class='hint-box'>{HINTS[f_algo]}</div>", unsafe_allow_html=True)

        if f_algo == "RSA":
            fk_col1, fk_col2 = st.columns([3, 1])
            with fk_col2:
                if st.button("Gen RSA", key="f_gen_rsa"):
                    pub, priv = generate_rsa_keys_simple()
                    st.session_state.f_gk = pub
                    st.info(f"Public: {pub} | Private: {priv}")
            with fk_col1:
                f_key = st.text_input("Key / Params:", value=st.session_state.get('f_gk', ''), key="f_key")
            s_val, s_txt, s_clr = check_key_strength(f_key)
            st.markdown(f"Strength: <b style='color:{s_clr}'>{s_txt}</b>", unsafe_allow_html=True)
            st.progress(min(s_val / 100, 1.0))
        else:
            f_key = st.text_input("Key / Params:", value="", key="f_key2")

        f_mode    = st.radio("Action:", ["Encrypt 🔒", "Decrypt 🔓"], horizontal=True, key="f_mode")
        f_run_btn = st.button("🚀 EXECUTE on File", key="f_run")

    with f_col2:
        st.subheader("📤 Output")

        if f_run_btn:
            if not uploaded_file:
                st.warning("⚠️ Please upload a .txt file first.")
            else:
                # قراءة محتوى الملف
                raw_content = uploaded_file.read().decode("utf-8", errors="ignore")
                is_enc = "Encrypt" in f_mode

                if   f_algo == "Caesar":        f_result = encrypt_caesar(raw_content, f_key)       if is_enc else decrypt_caesar(raw_content, f_key)
                elif f_algo == "ROT13":         f_result = rot13_encrypt(raw_content)
                elif f_algo == "Rail Fence":    f_result = rail_fence_encode(raw_content, f_key)    if is_enc else rail_fence_decode(raw_content, f_key)
                elif f_algo == "Reverse":       f_result = reverse_cipher(raw_content)
                elif f_algo == "RSA":           f_result = rsa_process_smart(raw_content, f_key, "ENCRYPT" if is_enc else "DECRYPT")
                elif f_algo == "Transposition": f_result = columnar_encrypt(raw_content, f_key)     if is_enc else columnar_decrypt(raw_content, f_key)
                elif f_algo == "Vigenere":      f_result = encrypt_vigenere(raw_content, f_key)     if is_enc else decrypt_vigenere(raw_content, f_key)
                elif f_algo == "XOR":           f_result = xor_encrypt(raw_content, f_key)          if is_enc else xor_decrypt(raw_content, f_key)
                elif f_algo == "Affine":        f_result = affine_encrypt(raw_content, f_key)       if is_enc else affine_decrypt(raw_content, f_key)
                elif f_algo == "Atbash":        f_result = atbash_cipher(raw_content)
                else:                           f_result = ""

                st.session_state.history.append({
                    "Time":   datetime.now().strftime("%H:%M"),
                    "Algo":   f_algo,
                    "Action": f_mode + " (file)",
                })

                # معاينة أول 500 حرف
                st.text_area("Preview (first 500 chars):", value=f_result[:500], height=200)

                # تحميل الملف الناتج
                action_label = "encrypted" if is_enc else "decrypted"
                out_filename = f"{action_label}_{uploaded_file.name}"
                st.download_button(
                    label="📥 Download Result File",
                    data=f_result.encode("utf-8"),
                    file_name=out_filename,
                    mime="text/plain",
                )

                if f_result:
                    st.markdown("### 📊 Frequency Analysis")
                    char_counts = pd.Series(list(f_result[:2000])).value_counts().reset_index().head(10)
                    char_counts.columns = ['Char', 'Count']
                    st.plotly_chart(
                        px.bar(char_counts, x='Char', y='Count', template="plotly_dark", height=250),
                        use_container_width=True,
                    )

# ── Sidebar ───────────────────────────────
with st.sidebar:
    st.markdown("<h2 style='color:#00ff88;'>📜 Activity Log</h2>", unsafe_allow_html=True)
    if st.session_state.history:
        st.table(pd.DataFrame(st.session_state.history).tail(5))

st.markdown("---")
st.markdown("<center style='color:#555;'>© 2026 Ebraam Saber</center>", unsafe_allow_html=True)
