import streamlit as st
import os
import hashlib
import json
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# info user data
user_data = "secure_user_data.json"
SALT = b'secret_salt-value'
LOCKOUT_DURATION = 60

# login details
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
    if "failed_attempts" not in st.session_state:
        st.session_state.failed_attempts = 0
    if "lockout_time" not in st.session_state:
        st.session_state.lockout_time = 0

        # if data load
def load_user_data():
    if os.path.exists(user_data):
        with open(user_data, "r") as f:
            return json.load(f)
    return {}

def save_user_data(data):
    with open(user_data, "w") as f:
        json.dump(data, f)


def generate_key(passkey):
    key = pbkdf2_hmac(
        'sha256',
        passkey.encode(),
        SALT,
        100000
    )
    return urlsafe_b64encode(key)
def hash_password(password):
    return hashlib.sha256(password.encode(), SALT,100000).hex()

      #cryptography.fernet 
def encrypt_data(text,key):  
    cipher = Fernet(generate_key(key))                 
    return cipher.encrypt(text.encode()).decode()
def decrypt_data(encrypted_text,key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None
    
    stored_data = load_data()
    # navigation bar
    # st.title("🔏Secure Data Encryption System")
    menu = ["Home","Login", "Registerd","Stored Data" "Retrieve"]
    choice = st.sidebar.selectbox("Navigation",menu)
    if choice =="Home":
        st.subheader("Secure Data Encryption System")
        st.markdown("Develop a Streamlit-based secure data storage and retrieval system where: "
                    "Users store data with a unique passkey. Users decrypt data by providing the correct passkey. "
                    "Multiple failed attempts result in a forced reauthorization (login page). "
                    "The system operates entirely in memory without external databases.")
# REgistration
    elif choice == "Register":
        st.subheader("✏️Register New User")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Register"):
            if username and password:
                user_data = load_user_data()
                if username in user_data:
                    st.error("⚠️Username already exists.")
                else:
                    hashed_password = hash_password(password)
                    user_data[username] = hashed_password
                    save_user_data(user_data)
                    st.success("🫱User registered successfully!")
            else:
                st.error("Please enter both username and password.")
    elif choice == "Login":
     st.subheader("🔑Login")
    if time.time() < st.session_state.lockout_time:
        remaining_time = int(st.session_state.lockout_time - time.time())
        st.error(f"⚠️Account locked. Try again in {remaining_time} seconds.")
        st.stop()
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in stored_data and stored_data[username] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"🔑Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining =3 - st.session_state.failed_attempts
            st.error(f"❌Invalid credentials. {remaining} attempts left.")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error(f"⚠️Account locked for {LOCKOUT_DURATION} 60 seconds.")
                st.stop()

                # Store data
                #   elif choice == "Store Data":
                if not st.session_state.authenticated_user:
                    st.warning("Please log in to store data.")
                else:
                    st.subheader("💾Store Data")
                    data = st.text_area("Enter data to store")
                    passkey = st.text_input("Enter passkey", type="password")
                    if st.button("Store"):
                        if data and passkey:
                            encrypted_data = encrypt_data(data, passkey)
                            stored_data[st.session_state.authenticated_user] = encrypted_data
                            save_user_data(stored_data)
                            st.success("Data stored successfully!")
                        else:
                            st.error("Please enter both data and passkey.")
           
           # Retrieve data
            elif choice == "Retrieve":
                if not st.session_state.authenticated_user:    
                 st.warning("Please log in to retrieve data.")
            else:
                st.subheader("🔍Retrieve Data")
            user_data = stored_data.get(st.session_state.authenticated_user, {})

            if not user_data:
                st.warning("No data found for the user.")
            else:
                st.write("Stored Data:")
                for i in enumerate(user_data):
                    st.code(item,language="text")
                    encrypted_input = st.text_area("Enter encrypted data to decrypt")
                    passkey = st.text_input("Enter passkey", type="password")
                    if st.button("Decrypt"):
                        result = decrypt_data(encrypted_input, passkey)
                        if result:
                            st.success(f"Decrypted data: {result}")
                        else:
                            st.error("❌Invalid passkey or decryption failed.")