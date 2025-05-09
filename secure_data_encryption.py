
import streamlit as st
import os
import hashlib
import json
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
USER_DATA_FILE = "secure_user_data.json"
SALT = b'secret_salt-value'
LOCKOUT_DURATION = 60

# Session state setup
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Load/save functions
def load_user_data():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_user_data(data):
    with open(USER_DATA_FILE, "w") as f:
        json.dump(data, f)

# Security functions
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_data(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Main app
stored_data = load_user_data()

st.title("🔏 Secure Data Encryption System")

menu = ["Home", "Login", "Register", "Store Data", "Retrieve"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home
if choice == "Home":
    st.subheader("Secure Data Encryption System")
    st.markdown("""
        This app allows users to:
        - Register and log in securely
        - Store encrypted data with a passkey
        - Retrieve and decrypt data
        - Auto-lock after failed login attempts
    """)

# Register
elif choice == "Register":
    st.subheader("✏️ Register New User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.error("⚠️ Username already exists.")
            else:
                hashed_password = hash_password(password)
                stored_data[username] = {"password": hashed_password, "data": []}
                save_user_data(stored_data)
                st.success("🫱 User registered successfully!")
        else:
            st.error("Please enter both username and password.")

# Login
elif choice == "Login":
    st.subheader("🔑 Login")
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⚠️ Account locked. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"🔓 Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. {remaining} attempts left.")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.stop()

# Store Data
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please log in to store data.")
    else:
        st.subheader("💾 Store Data")
        data = st.text_area("Enter data to store")
        passkey = st.text_input("Enter passkey", type="password")
        if st.button("Store"):
            if data and passkey:
                encrypted = encrypt_data(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_user_data(stored_data)
                st.success("✅ Data stored successfully!")
            else:
                st.error("Please enter both data and passkey.")

# Retrieve Data
elif choice == "Retrieve":
    if not st.session_state.authenticated_user:
        st.warning("Please log in to retrieve data.")
    else:
        st.subheader("🔍 Retrieve Data")
        user_items = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
        if not user_items:
            st.warning("No data found for this user.")
        else:
            for i, item in enumerate(user_items, start=1):
                st.markdown(f"**Encrypted Item {i}:**")
                st.code(item, language="text")

                decrypt = st.checkbox(f"Decrypt item {i}")
                if decrypt:
                    encrypted_input = item
                    passkey = st.text_input(f"Passkey for item {i}", type="password", key=f"passkey_{i}")
                    if st.button(f"Decrypt Item {i}"):
                        result = decrypt_data(encrypted_input, passkey)
                        if result:
                            st.success(f"🔓 Decrypted data: {result}")
                        else:
                            st.error("❌ Invalid passkey or decryption failed.")
