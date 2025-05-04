# 🔹 Streamlit for UI
import streamlit as st
# 🔹 Cryptography for secure encryption/decryption
from cryptography.fernet import Fernet
# 🔹 Hashing for passkeys and passwords
import hashlib


# --- Session Initialization ---
if "users" not in st.session_state:
    st.session_state.users = {}  # {"username": {"password": hashed_pw}}

if "logged_in_user" not in st.session_state:
    st.session_state.logged_in_user = None

if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.fernet_key)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {"username": {encrypted_text: {passkey, ...}}}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0


# --- Hashing ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


# --- Encryption / Decryption ---
def encrypt_data(text, passkey):
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, stored_passkey_hash, entered_passkey):
    if stored_passkey_hash == hash_passkey(entered_passkey):
        st.session_state.failed_attempts = 0
        return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None


# --- UI ---
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Show login status
if st.session_state.logged_in_user:
    st.sidebar.success(f"Logged in as: {st.session_state.logged_in_user}")
    if st.sidebar.button("🚪 Logout"):
        st.session_state.logged_in_user = None
        st.success("✅ Logged out successfully.")
        st.rerun()

# --- Home ---
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# --- Store Data ---
elif choice == "Store Data":
    if not st.session_state.logged_in_user:
        st.warning("🔐 Please log in to store data.")
        st.stop()

    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            user = st.session_state.logged_in_user
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)

            if user not in st.session_state.stored_data:
                st.session_state.stored_data[user] = {}

            st.session_state.stored_data[user][encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }

            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Both fields are required!")

# --- Retrieve Data ---
elif choice == "Retrieve Data":
    if not st.session_state.logged_in_user:
        st.warning("🔐 Please log in to retrieve data.")
        st.stop()

    st.subheader("🔍 Retrieve Your Data")
    user = st.session_state.logged_in_user
    user_data = st.session_state.stored_data.get(user, {})
    encrypted_options = list(user_data.keys())

    if encrypted_options:
        encrypted_text = st.selectbox("Select Encrypted Entry:", encrypted_options)
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                stored_entry = user_data.get(encrypted_text)
                decrypted = decrypt_data(encrypted_text, stored_entry["passkey"], passkey)

                if decrypted:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted, language="text")
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                        st.rerun()
            else:
                st.error("⚠️ Both fields are required!")
    else:
        st.info("ℹ️ No stored data available.")

# --- Login/Register ---
elif choice == "Login":
    tab = st.tabs(["🔐 Login", "📝 Register"])

    # Login Tab
    with tab[0]:
        st.subheader("🔑 User Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            user = st.session_state.users.get(username)
            if user and user["password"] == hash_password(password):
                st.session_state.logged_in_user = username
                st.session_state.failed_attempts = 0
                st.success(f"✅ Welcome back, {username}!")
                st.rerun()
            else:
                st.error("❌ Invalid username or password!")

    # Register Tab
    with tab[1]:
        st.subheader("📝 Register New Account")
        new_username = st.text_input("Choose Username")
        new_password = st.text_input("Choose Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")

        if st.button("Register"):
            if new_password != confirm_password:
                st.error("❌ Passwords do not match!")
            elif new_username in st.session_state.users:
                st.error("❌ Username already taken!")
            else:
                st.session_state.users[new_username] = {
                    "password": hash_password(new_password)
                }
                st.success("✅ Registration successful! You can now log in.")
