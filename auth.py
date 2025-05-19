import os
import hashlib
import pyotp
import qrcode
import datetime
from argon2 import PasswordHasher, low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import User, UserSymmetricKeys, LoginAttempts, Logs
import base64
import getpass
import sys
from pathlib import Path

engine = create_engine('sqlite:///myfinance.db')
Session = sessionmaker(bind=engine)
session = Session()


def log_audit(user_id, action, description, session):
    try:
        master_passphrase = get_master_key()
        salt = hashlib.sha256(master_passphrase).digest()[:16]
        key_material = low_level.hash_secret_raw(
            secret=master_passphrase,
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=64,
            type=low_level.Type.ID
        )
        master_encryption_key = key_material[:32]

        master_aesgcm = AESGCM(master_encryption_key)

        description_iv = os.urandom(12)
        encrypted_description = master_aesgcm.encrypt(
            description_iv,
            description.encode(),
            None
        )

        audit_entry = Logs(
            user_id=user_id,
            action=action,
            description=base64.b64encode(encrypted_description).decode('utf-8'),
            description_iv=base64.b64encode(description_iv).decode('utf-8'),
            timestamp=datetime.datetime.now()
        )
        session.add(audit_entry)
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"Error logging action: {e}")
    finally:
        session.close()


def get_master_key():
    key_path = Path("hardware_security_module") / ("master_key") / ("master.key")

    if key_path.exists():
        with open(key_path, 'rb') as key_file:
            return key_file.read()
    else:
        return "default_master_key".encode()


def clear_screen():
    print("\n" * 200)


def sanitise_string(text):
    return ''.join(char for char in text if ord(char) < 0xD800 or ord(char) > 0xDFFF)


def register():
    print("-" * 200)
    print("Register with My Finance Inc.")
    print("-" * 200)
    get_full_name = input("Enter your full name: ")

    while True:
        get_email = input("Enter your email: ")
        if "@" not in get_email or "." not in get_email:
            print("Email is in the wrong format.")
        else:
            email_exists = False
            all_users = session.query(User).all()

            master_passphrase = get_master_key()
            salt = hashlib.sha256(master_passphrase).digest()[:16]
            key_material = low_level.hash_secret_raw(secret=master_passphrase, salt=salt, time_cost=3,
                                                     memory_cost=65536, parallelism=4, hash_len=64,
                                                     type=low_level.Type.ID)
            master_encryption_key = key_material[:32]
            master_aesgcm = AESGCM(master_encryption_key)

            for user in all_users:
                try:
                    sym_key = session.query(UserSymmetricKeys).filter(
                        UserSymmetricKeys.user_id == user.user_id,
                        UserSymmetricKeys.active == True
                    ).first()

                    if not sym_key:
                        continue

                    dek_iv = base64.b64decode(sym_key.dek_iv)
                    encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
                    user_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

                    user_aesgcm = AESGCM(user_dek)
                    email_iv = base64.b64decode(user.email_iv)
                    encrypted_email = base64.b64decode(user.email)
                    decrypted_email = user_aesgcm.decrypt(email_iv, encrypted_email, None).decode('utf-8')

                    if decrypted_email.lower() == get_email.lower():
                        email_exists = True
                        break
                except UnicodeEncodeError:
                    print("The email contains invalid characters. Please enter a valid email address.")
                except Exception:
                    continue

            if email_exists:
                print("This email is already registered. Please use a different email.")
            else:
                break

    while True:
        try:
            get_phone = int(input("Enter your phone number: "))

            phone_exists = False
            all_users = session.query(User).all()

            for user in all_users:
                try:
                    sym_key = session.query(UserSymmetricKeys).filter(
                        UserSymmetricKeys.user_id == user.user_id,
                        UserSymmetricKeys.active == True
                    ).first()

                    if not sym_key:
                        continue

                    dek_iv = base64.b64decode(sym_key.dek_iv)
                    encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
                    user_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

                    user_aesgcm = AESGCM(user_dek)
                    phone_iv = base64.b64decode(user.phone_iv)
                    encrypted_phone = base64.b64decode(user.phone)
                    decrypted_phone = user_aesgcm.decrypt(phone_iv, encrypted_phone, None).decode('utf-8')

                    if decrypted_phone == str(get_phone):
                        phone_exists = True
                        break
                except Exception:
                    continue

            if phone_exists:
                print("This phone number is already registered. Please use a different phone number.")
            else:
                break
        except ValueError:
            print("Phone number should be numerical.")

    get_username = input("Enter your username: ")

    while True:
        existing_user = session.query(User).filter(User.username == get_username).first()
        if existing_user:
            print("This username is already taken. Please choose a different username.")
            get_username = input("Enter your username: ")
        else:
            break

    print("-" * 200)
    while True:
        print("""Enter your password. Your password must have:
- 8 characters minimum
- Contain one capital letter
- Contain one number
- Contain one special character""")
        try:
            if sys.stdin.isatty():
                passwords_match = False
                print("\nYour password will be masked and won't be visible.")
                print("Please continue to enter your password.")
                while passwords_match != True:
                    get_password = getpass.getpass("\nEnter Password: ")
                    get_password2 = getpass.getpass("Enter Password Again: ")

                    if get_password == get_password2:
                        passwords_match = True
                    else:
                        print("Your passwords don't match.")
            else:
                raise OSError
        except OSError:
            print("\nIt seems like your console doesn't fully support features like disabling input echo.")
            print("Your password can't masked and will be visible to you because input echo can't be disabled.")
            print("Try running this program in a system terminal to fix the issue.")
            passwords_match = False
            while passwords_match != True:
                get_password = input("\nEnter Password: ")
                get_password2 = input("Enter Password Again: ")
                if get_password == get_password2:
                    passwords_match = True
                else:
                    print("Your passwords don't match.")

        if (len(get_password) >= 8 and
                any(c.isupper() for c in get_password) and
                any(c.isdigit() for c in get_password) and
                any(c in "!@#$%^&*()-_+=<>?/|{}[]" for c in get_password)):
            break
        else:
            print("Your password is too weak.")
            print("-" * 200)

    print("-" * 200)
    role_is_valid = False
    while role_is_valid != True:
        print("What is your role?")
        print("- If you are a client, enter '1'.")
        print("- If you are a advisor, enter '2'.")
        print("- If you are an administrator, enter '3'.")
        get_role = input("\nSelect: ")
        if get_role not in ['1', '2', '3']:
            print("You haven't selected your role correctly.")
        else:
            role_is_valid = True

    if get_role == "1":
        user_role = "client"
    elif get_role == "2":
        user_role = "advisor"
    elif get_role == "3":
        user_role = "admin"

    print("-" * 200)
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(get_username, issuer_name="MyFinance Inc.")

    print("Your QR Code should appear in another window.")
    print("Please use an authenticator app (e.g. Google Authenticator, Microsoft Authenticator) to scan the QR code.")
    print(f"OTP URI: {otp_uri}")
    qr = qrcode.make(otp_uri)
    qr.show()

    while True:
        mfa_check = input("\nEnter the code from your authenticator app to confirm setup: ")
        if totp.verify(mfa_check):
            break
        else:
            print("Invalid MFA code. Please try again.")

            retry = input("Do you want to try again? (y/n): ")
            if retry.lower() != 'y':
                print("Registration cancelled.")
                return

    master_passphrase = get_master_key()
    salt = hashlib.sha256(master_passphrase).digest()[:16]
    key_material = low_level.hash_secret_raw(secret=master_passphrase, salt=salt, time_cost=3, memory_cost=65536,
                                             parallelism=4, hash_len=64, type=low_level.Type.ID)

    master_encryption_key = key_material[:32]
    hmac_key = key_material[32:]

    user_dek = os.urandom(32)

    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
    password_hash = ph.hash(get_password)

    user_aesgcm = AESGCM(user_dek)
    email_iv = os.urandom(12)
    get_email = sanitise_string(get_email)
    encrypted_email = user_aesgcm.encrypt(email_iv, get_email.encode(), None)
    phone_iv = os.urandom(12)
    encrypted_phone = user_aesgcm.encrypt(phone_iv, str(get_phone).encode(), None)
    full_name_iv = os.urandom(12)
    encrypted_full_name = user_aesgcm.encrypt(full_name_iv, get_full_name.encode(), None)

    mfa_secret_iv = os.urandom(12)
    encrypted_mfa_secret = user_aesgcm.encrypt(mfa_secret_iv, secret.encode(), None)

    new_user = User(
        username=get_username,
        password=password_hash,
        role=user_role,
        email=base64.b64encode(encrypted_email).decode('utf-8'),
        email_iv=base64.b64encode(email_iv).decode('utf-8'),
        phone=base64.b64encode(encrypted_phone).decode('utf-8'),
        phone_iv=base64.b64encode(phone_iv).decode('utf-8'),
        full_name=base64.b64encode(encrypted_full_name).decode('utf-8'),
        full_name_iv=base64.b64encode(full_name_iv).decode('utf-8'),
        mfa_secret=base64.b64encode(encrypted_mfa_secret).decode('utf-8'),
        mfa_secret_iv=base64.b64encode(mfa_secret_iv).decode('utf-8'),
        locked=False
    )
    session.add(new_user)
    session.flush()

    master_aesgcm = AESGCM(master_encryption_key)
    dek_iv = os.urandom(12)
    encrypted_dek = master_aesgcm.encrypt(dek_iv, user_dek, None)

    symmetric_key = UserSymmetricKeys(
        user_id=new_user.user_id,
        encrypted_dek=base64.b64encode(encrypted_dek).decode('utf-8'),
        dek_iv=base64.b64encode(dek_iv).decode('utf-8'),
        created_at=datetime.datetime.now(),
        active=True
    )
    session.add(symmetric_key)

    print("-" * 200)
    session.commit()
    print(f"Registration successful for {get_username}!")
    return new_user.user_id, user_role, get_full_name
    session.close()


def login():
    session = Session()
    print("-" * 200)
    print("Login to MyFinance Inc.")
    print("-" * 200)

    username = input("Enter your username: ")

    user = session.query(User).filter(User.username == username).first()
    if not user:
        print("Invalid username or password.")
        return None

    if user.locked:
        failed_attempts = session.query(LoginAttempts).filter(
            LoginAttempts.user_id == user.user_id,
            LoginAttempts.success == False
        ).order_by(LoginAttempts.timestamp.desc()).first()

        if failed_attempts and failed_attempts.timestamp:
            lockout_time = failed_attempts.timestamp + datetime.timedelta(minutes=15)
            now = datetime.datetime.now()

            if now < lockout_time:
                time_remaining = int((lockout_time - now).total_seconds() / 60)
                print(f"Your account is locked due to multiple failed login attempts.")
                print(f"Please try again after {time_remaining} minutes.")
                return None
            else:
                user.locked = False
                session.commit()
        else:
            print("Your account is locked. Please contact an administrator.")
            return None

    try:
        if sys.stdin.isatty():
            print("\nYour password will be masked and won't be visible.")
            print("Please continue to enter your password.")
            password = getpass.getpass("\nEnter Password (input masked): ")
        else:
            raise OSError
    except OSError:
        print("\nIt seems like your console doesn't fully support features like disabling input echo.")
        print("Your password can't be masked and will be visible to you because input echo can't be disabled.")
        print("Try running this program in a system terminal to fix the issue.")

        password = input("\nEnter Password (input not masked): ")

    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

    try:
        if not password or password.strip() == "":
            raise ValueError("Password cannot be empty")

        ph.verify(user.password, password)

        if ph.check_needs_rehash(user.password):
            new_hash = ph.hash(password)
            user.password = new_hash
            session.commit()

    except Exception as e:
        login_attempt = LoginAttempts(
            user_id=user.user_id,
            timestamp=datetime.datetime.now(),
            success=False
        )

        session.add(login_attempt)
        session.commit()

        failed_count = session.query(LoginAttempts).filter(
            LoginAttempts.user_id == user.user_id,
            LoginAttempts.success == False,
            LoginAttempts.timestamp >= datetime.datetime.now() - datetime.timedelta(hours=1)
        ).count()

        if failed_count >= 3:
            user.locked = True
            log_audit(user.user_id, "Failed Login",
                      f"User '{username}' failed to log in 3 times and is now locked out.", session)
            print("Too many failed login attempts. Your account has been locked for 15 minutes.")
        else:
            remaining_attempts = 3 - failed_count
            log_audit(user.user_id, "Failed Login", f"User '{username}' failed to log in.", session)
            print(f"Invalid username or password. {remaining_attempts} attempts remaining before lockout.")

        session.commit()
        return None

    master_passphrase = get_master_key()
    salt = hashlib.sha256(master_passphrase).digest()[:16]
    key_material = low_level.hash_secret_raw(secret=master_passphrase, salt=salt, time_cost=3, memory_cost=65536,
                                             parallelism=4, hash_len=64, type=low_level.Type.ID)
    master_encryption_key = key_material[:32]

    sym_key = session.query(UserSymmetricKeys).filter(
        UserSymmetricKeys.user_id == user.user_id,
        UserSymmetricKeys.active == True
    ).first()

    if not sym_key:
        print("Error: Could not retrieve encryption keys")
        return None

    try:
        master_aesgcm = AESGCM(master_encryption_key)
        dek_iv = base64.b64decode(sym_key.dek_iv)
        encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
        user_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

        user_aesgcm = AESGCM(user_dek)

        if user.mfa_secret and user.mfa_secret_iv:
            mfa_secret_iv = base64.b64decode(user.mfa_secret_iv)
            encrypted_mfa_secret = base64.b64decode(user.mfa_secret)
            mfa_secret = user_aesgcm.decrypt(mfa_secret_iv, encrypted_mfa_secret, None).decode('utf-8')

            print("-" * 200)

            while True:
                totp_code = input("Enter the code from your authenticator app: ")
                totp = pyotp.TOTP(mfa_secret)

                if not totp.verify(totp_code):
                    login_attempt = LoginAttempts(
                        user_id=user.user_id,
                        timestamp=datetime.datetime.now(),
                        success=False
                    )
                    session.add(login_attempt)
                    session.commit()

                    print("Invalid MFA code.")
                    retry = input("Do you want to try again? (y/n): ")
                    if retry.lower() != 'y':
                        return None
                    else:
                        print("Please try again.")
                else:
                    login_attempt = LoginAttempts(
                        user_id=user.user_id,
                        timestamp=datetime.datetime.now(),
                        success=True
                    )
                    session.add(login_attempt)
                    session.commit()
                    break

        else:
            print("-" * 200)
            print("MFA setup required")
            print("-" * 200)
            print("Please set up Multi-Factor Authentication for your account.")

            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret)
            otp_uri = totp.provisioning_uri(username, issuer_name="MyFinance Inc.")

            print("\nYour QR Code will appear in a new window.")
            print("Please scan it with an authenticator app (e.g. Google Authenticator, Microsoft Authenticator).")
            qr = qrcode.make(otp_uri)
            qr.show()

            while True:
                mfa_check = input("Enter the code from your authenticator app to confirm setup: ")
                if totp.verify(mfa_check):
                    mfa_secret_iv = os.urandom(12)
                    encrypted_mfa_secret = user_aesgcm.encrypt(mfa_secret_iv, secret.encode(), None)

                    user.mfa_secret = base64.b64encode(encrypted_mfa_secret).decode('utf-8')
                    user.mfa_secret_iv = base64.b64encode(mfa_secret_iv).decode('utf-8')
                    session.commit()

                    print("MFA setup complete!")
                    break
                else:
                    print("Invalid MFA code. Please try again.")
                    retry = input("Do you want to try again? (y/n): ")
                    if retry.lower() != 'y':
                        print("MFA setup cancelled. You won't be able to login without completing MFA setup.")
                        break
                        return None

        session.query(LoginAttempts).filter(
            LoginAttempts.user_id == user.user_id,
            LoginAttempts.success == False,
            LoginAttempts.timestamp >= datetime.datetime.now() - datetime.timedelta(hours=1)
        ).delete()

        full_name_iv = base64.b64decode(user.full_name_iv)
        encrypted_full_name = base64.b64decode(user.full_name)
        decrypted_full_name = user_aesgcm.decrypt(full_name_iv, encrypted_full_name, None).decode('utf-8')

        login_attempt = LoginAttempts(
            user_id=user.user_id,
            timestamp=datetime.datetime.now(),
            success=True
        )
        session.add(login_attempt)
        session.commit()

        print("-" * 200)
        print(f"Login successful! Welcome, {decrypted_full_name}!")

        return user.user_id, user.role, decrypted_full_name
    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        session.close()