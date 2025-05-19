from clients_and_advisors import *
import os
import base64
import hashlib
import datetime
from argon2 import PasswordHasher, low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from models import Base, User, UserSymmetricKeys, Logs, LoginAttempts
from pathlib import Path

def sanitise_string(text):
    return ''.join(char for char in text if ord(char) < 0xD800 or ord(char) > 0xDFFF)

def clear_screen():
    print("\n" * 200)

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


def get_master_key():
    key_path = Path("hardware_security_module") / ("master_key") / ("master.key")

    if key_path.exists():
        with open(key_path, 'rb') as key_file:
            return key_file.read()
    else:
        return "default_master_key".encode()

def decrypt_audit_log(log_entry, user_aesgcm):
    if not log_entry.description or not log_entry.description_iv:
        return "No description available"

    try:
        description_iv = base64.b64decode(log_entry.description_iv)
        encrypted_description = base64.b64decode(log_entry.description)

        decrypted_description = user_aesgcm.decrypt(
            description_iv,
            encrypted_description,
            None
        ).decode('utf-8')

        return decrypted_description
    except Exception as e:
        return f"Error decrypting description: {e}"

def admin_create_user(admin_id, admin_full_name, session):
    print("-" * 200)
    print("Create New User Account")
    print("-" * 200)
    get_full_name = input("Enter user's full name: ")

    while True:
        get_email = input("Enter user's email: ")
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
                except Exception:
                    continue

            if email_exists:
                print("This email is already registered. Please use a different email.")
            else:
                break

    while True:
        try:
            get_phone = int(input("Enter user's phone number: "))

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

    get_username = input("Enter username for the account: ")

    while True:
        existing_user = session.query(User).filter(User.username == get_username).first()
        if existing_user:
            print("This username is already taken. Please choose a different username.")
            get_username = input("Enter username: ")
        else:
            break

    print("-" * 200)
    print("""Set user password. The password must have:
- 8 characters minimum
- Contain one capital letter
- Contain one number
- Contain one special character""")

    while True:
        get_password = input("\nEnter password for the user: ")
        confirm_password = input("Confirm password: ")

        if get_password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue

        if (len(get_password) >= 8 and
                any(c.isupper() for c in get_password) and
                any(c.isdigit() for c in get_password) and
                any(c in "!@#$%^&*()-_+=<>?/|{}[]" for c in get_password)):
            break
        else:
            print("Password does not meet security requirements.")

    print("-" * 200)
    print("Select user role:")
    print("- Enter '1' for a client")
    print("- Enter '2' for an advisor")
    print("- Enter '3' for an admin")

    role_choice = ""
    while role_choice not in ["1", "2", "3"]:
        role_choice = input("\nSelect: ")

    if role_choice == "1":
        user_role = "client"
    elif role_choice == "2":
        user_role = "advisor"
    elif role_choice == "3":
        user_role = "admin"

    master_passphrase = get_master_key()
    salt = hashlib.sha256(master_passphrase).digest()[:16]
    key_material = low_level.hash_secret_raw(secret=master_passphrase, salt=salt, time_cost=3, memory_cost=65536,
                                             parallelism=4, hash_len=64, type=low_level.Type.ID)

    master_encryption_key = key_material[:32]

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
        mfa_secret=None,
        mfa_secret_iv=None,
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
    print(f"Account created successfully for {get_full_name}!")
    print(f"Username: {get_username}")
    print(f"Role: {user_role}")
    print("\nThe user will need to set up MFA on first login.")

    log_audit(admin_id, "Create New User",f"The administrator '{admin_full_name}' created an account for the {user_role} '{get_full_name}'.", session)


def view_all_users():
    print("-" * 200)
    print("All Users in the System")
    print("-" * 200)

    all_users = session.query(User).all()

    if not all_users:
        print("No users found.")
        return

    master_passphrase = get_master_key()
    salt = hashlib.sha256(master_passphrase).digest()[:16]
    key_material = low_level.hash_secret_raw(secret=master_passphrase, salt=salt, time_cost=3, memory_cost=65536,
                                             parallelism=4, hash_len=64, type=low_level.Type.ID)
    master_encryption_key = key_material[:32]
    master_aesgcm = AESGCM(master_encryption_key)

    print(f"{'ID':<10} {'Username':<15} {'Role':<15} {'Full Name':<25} {'Email':<25} {'Status':<10}")
    print("-" * 200)

    for user in all_users:
        try:
            sym_key = session.query(UserSymmetricKeys).filter(
                UserSymmetricKeys.user_id == user.user_id,
                UserSymmetricKeys.active == True
            ).first()

            if not sym_key:
                print(f"{user.user_id:<10} {user.username:<15} {user.role:<15} {'Error: No encryption key':<25}")
                continue

            dek_iv = base64.b64decode(sym_key.dek_iv)
            encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
            user_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

            user_aesgcm = AESGCM(user_dek)

            name_iv = base64.b64decode(user.full_name_iv)
            encrypted_name = base64.b64decode(user.full_name)
            full_name = user_aesgcm.decrypt(name_iv, encrypted_name, None).decode('utf-8')

            email_iv = base64.b64decode(user.email_iv)
            encrypted_email = base64.b64decode(user.email)
            email = user_aesgcm.decrypt(email_iv, encrypted_email, None).decode('utf-8')

            status = "Locked" if user.locked else "Active"

            print(
                f"{user.user_id:<10} {user.username:<15} {user.role:<15} {full_name[:23]:<25} {email[:23]:<25} {status:<10}")

        except Exception as e:
            print(f"{user.user_id:<10} {user.username:<15} {user.role:<15} {'Error: ' + str(e)[:20]:<25}")

    print("-" * 200)

def manage_user_lock(admin_id, admin_full_name, session):
    print("-" * 200)
    print("Lock/Unlock User Account")
    print("-" * 200)

    master_passphrase = get_master_key()
    salt = hashlib.sha256(master_passphrase).digest()[:16]
    key_material = low_level.hash_secret_raw(secret=master_passphrase, salt=salt, time_cost=3, memory_cost=65536,
                                             parallelism=4, hash_len=64, type=low_level.Type.ID)
    master_encryption_key = key_material[:32]
    master_aesgcm = AESGCM(master_encryption_key)

    all_users = session.query(User).all()

    print(f"{'ID':<10} {'Username':<20} {'Full Name':<30} {'Role':<20} {'Status':<20}")
    print("-" * 200)

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
            name_iv = base64.b64decode(user.full_name_iv)
            encrypted_name = base64.b64decode(user.full_name)
            full_name = user_aesgcm.decrypt(name_iv, encrypted_name, None).decode('utf-8')

            status = "Locked" if user.locked else "Active"
            print(f"{user.user_id:<10} {user.username:<20} {full_name[:23]:<30} {user.role:<20} {status:<20}")
        except Exception:
            continue

    print("-" * 200)

    try:
        user_id = int(input("Enter user ID to manage: "))
        user = session.query(User).filter(User.user_id == user_id).first()

        if not user:
            print(f"No user found with ID {user_id}")
            return

        sym_key = session.query(UserSymmetricKeys).filter(
            UserSymmetricKeys.user_id == user_id,
            UserSymmetricKeys.active == True
        ).first()

        if not sym_key:
            print("Error: Could not retrieve encryption keys")
            return

        dek_iv = base64.b64decode(sym_key.dek_iv)
        encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
        user_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

        user_aesgcm = AESGCM(user_dek)
        name_iv = base64.b64decode(user.full_name_iv)
        encrypted_name = base64.b64decode(user.full_name)
        full_name = user_aesgcm.decrypt(name_iv, encrypted_name, None).decode('utf-8')

        status = "Locked" if user.locked else "Active"
        print(f"\nUser: {full_name}")
        print(f"Username: {user.username})")
        print(f"Current status: {status}")

        action = "unlock" if user.locked else "lock"
        confirm = input(f"Do you want to {action} this account? (y/n): ")

        if confirm.lower() == 'y':
            log_audit(admin_id, f"{action.capitalize()} User Account", f"The administrator '{admin_full_name}' has {action}ed the user account of '{full_name}'.", session)
            user.locked = not user.locked
            session.commit()
            new_status = "Locked" if user.locked else "Active"
            print(f"\nAccount status updated. New status: {new_status}")
        else:
            print("\nAction cancelled.")

    except ValueError:
        print("Please enter a valid user ID.\n")
    except Exception as e:
        print(f"Error: {e}\n")

def view_audit_logs(session):
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

        logs = session.query(Logs).order_by(Logs.audit_id.desc()).all()

        print("-" * 250)
        print("MyFinance Inc. Audit Logs")
        print("-" * 250)

        print("{:<10} {:<25} {:<25} {:<40} {:<150}".format(
            "ID", "Timestamp", "User / System", "Action", "Description"))
        print("-" * 250)

        for log in logs:
            # Get username if available
            if log.user_id:
                user = session.query(User).filter(User.user_id == log.user_id).first()
                username = user.username if user else f"User {log.user_id}"
            else:
                username = "System"

            try:
                # Decrypt using master key directly
                description_iv = base64.b64decode(log.description_iv)
                encrypted_description = base64.b64decode(log.description)
                description = master_aesgcm.decrypt(description_iv, encrypted_description, None).decode('utf-8')
            except Exception as e:
                description = f"Decryption Error: {str(e)}"

            print("{:<10} {:<25} {:<25} {:<40} {:<150}".format(
                log.audit_id,
                log.timestamp.strftime('%d %b %Y, %H:%M'),
                username,
                log.action,
                description
            ))

        input("\nHit Enter to continue.")

    except Exception as e:
        print(f"Error viewing audit logs: {e}")
        input("\nHit Enter to continue.")
