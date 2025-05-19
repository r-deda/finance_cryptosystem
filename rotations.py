import subprocess
import uuid
from sqlalchemy import create_engine, or_
from sqlalchemy.orm import sessionmaker
from models import User, Portfolio, Transaction, UserSymmetricKeys, Logs
from secure_messaging import generate_asymmetric_key_pair
from key_backups import *
import os
import base64
import datetime
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import low_level

engine = create_engine('sqlite:///myfinance.db')
Session = sessionmaker(bind=engine)

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

def check_certificate_validity(cert_path):
    if not os.path.exists(cert_path):
        return False

    try:
        cmd = f"openssl x509 -enddate -noout -in {cert_path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            return False

        end_date_line = result.stdout.strip()
        date_str = end_date_line.split('=')[1]
        expiry_date = datetime.datetime.strptime(date_str, '%d %b %Y, %H:%M')

        return (expiry_date - datetime.datetime.now()).days > 1

    except Exception as e:
        print(f"Error checking certificate validity: {e}")
        return False

def generate_certificates():
    cert_dir = Path("hardware_security_module") / ("certificates")
    cert_dir.mkdir(exist_ok=True, mode=0o700)

    key_path = cert_dir / "server.key"
    csr_path = cert_dir / "server.csr"
    cert_path = cert_dir / "server.crt"

    try:
        instance_id = str(uuid.uuid4())[:8]

        key_cmd = f"openssl genrsa -out {key_path} 2048"
        subprocess.run(key_cmd, shell=True, check=True)

        os.chmod(key_path, 0o600)

        csr_cmd = (f'openssl req -new -key {key_path} -out {csr_path} '
                   f'-subj "/C=GB/ST=Warwickshire/L=Coventry/O=MyFinance Inc./OU=Security/CN=myfinance-{instance_id}.local"')
        subprocess.run(csr_cmd, shell=True, check=True)

        cert_cmd = (f'openssl x509 -req -days 365 -in {csr_path} -signkey {key_path} '
                    f'-out {cert_path} -sha256')
        subprocess.run(cert_cmd, shell=True, check=True)

        os.chmod(csr_path, 0o600)
        os.chmod(cert_path, 0o644)

        fingerprint_cmd = f"openssl x509 -in {cert_path} -noout -fingerprint -sha256"
        fingerprint = subprocess.run(fingerprint_cmd, shell=True, capture_output=True, text=True)
        print("Certificate generated successfully.")
        print(f"Certificate Fingerprint (SHA256): {fingerprint.stdout.strip()}")
        print("Users should verify this fingerprint when connecting for the first time.")

        return str(cert_path), str(key_path)

    except subprocess.SubprocessError as e:
        print(f"Error generating certificates: {e}")
        print("Please ensure OpenSSL is installed and in your PATH.")
        return None, None
    except Exception as e:
        print(f"Unexpected error during certificate generation: {e}")
        return None, None

def rotate_certificates(admin_id, admin_full_name):
    print("-" * 200)
    print("TLS Certificate Rotation")
    print("-" * 200)
    print("WARNING: This will generate new TLS certificates for the server.")
    confirm = input("Are you sure you want to proceed? (y/n): ")

    if confirm.lower() != 'y':
        print("Certificate rotation cancelled.")
        return

    try:
        cert_path, key_path = generate_certificates()

        if cert_path and key_path:
            print("-" * 200)
            print("TLS Certificates Rotated Successfully!")
            print(f"New Certificate Path: {cert_path}")
            print(f"New Key Path: {key_path}")
            print("-" * 200)
            log_audit(admin_id, "Certificate Rotation", f"The administrator '{admin_full_name}' has rotated the certificates.", Session())

        else:
            print("Failed to generate new certificates.")

    except Exception as e:
        print(f"Error during certificate rotation: {e}")

def rotate_symmetric_keys(admin_id, admin_full_name):
    print("-" * 200)
    print("Symmetric Key Rotations")
    print("-" * 200)
    print("WARNING: This will generate new symmetric encryption keys for all data in the system.")
    confirm = input("Are you sure you want to proceed? (y/n): ")

    if confirm.lower() != 'y':
        print("Key rotation cancelled.")
        return

    main_session = Session()

    try:
        all_users = main_session.query(User).all()

        if not all_users:
            print("No users found in the system.")
            return

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

        rotated_count = 0
        failed_count = 0

        audit_messages = []

        for user in all_users:
            user_session = Session()
            try:
                print(f"Rotating keys for user: {user.username}...")

                current_user = user_session.query(User).filter(User.user_id == user.user_id).first()

                active_key = user_session.query(UserSymmetricKeys).filter(
                    UserSymmetricKeys.user_id == current_user.user_id,
                    UserSymmetricKeys.active == True
                ).first()

                if not active_key:
                    print(f"No active key found for {current_user.username}, skipping...")
                    failed_count += 1
                    user_session.close()
                    continue

                dek_iv = base64.b64decode(active_key.dek_iv)
                encrypted_dek = base64.b64decode(active_key.encrypted_dek)
                current_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

                current_aesgcm = AESGCM(current_dek)

                new_dek = os.urandom(32)
                new_aesgcm = AESGCM(new_dek)

                new_dek_iv = os.urandom(12)
                new_encrypted_dek = master_aesgcm.encrypt(new_dek_iv, new_dek, None)

                email_iv = base64.b64decode(current_user.email_iv)
                encrypted_email = base64.b64decode(current_user.email)
                decrypted_email = current_aesgcm.decrypt(email_iv, encrypted_email, None)

                new_email_iv = os.urandom(12)
                new_encrypted_email = new_aesgcm.encrypt(new_email_iv, decrypted_email, None)

                current_user.email = base64.b64encode(new_encrypted_email).decode('utf-8')
                current_user.email_iv = base64.b64encode(new_email_iv).decode('utf-8')

                phone_iv = base64.b64decode(current_user.phone_iv)
                encrypted_phone = base64.b64decode(current_user.phone)
                decrypted_phone = current_aesgcm.decrypt(phone_iv, encrypted_phone, None)

                new_phone_iv = os.urandom(12)
                new_encrypted_phone = new_aesgcm.encrypt(new_phone_iv, decrypted_phone, None)

                current_user.phone = base64.b64encode(new_encrypted_phone).decode('utf-8')
                current_user.phone_iv = base64.b64encode(new_phone_iv).decode('utf-8')

                full_name_iv = base64.b64decode(current_user.full_name_iv)
                encrypted_full_name = base64.b64decode(current_user.full_name)
                decrypted_full_name = current_aesgcm.decrypt(full_name_iv, encrypted_full_name, None)

                new_full_name_iv = os.urandom(12)
                new_encrypted_full_name = new_aesgcm.encrypt(new_full_name_iv, decrypted_full_name, None)

                current_user.full_name = base64.b64encode(new_encrypted_full_name).decode('utf-8')
                current_user.full_name_iv = base64.b64encode(new_full_name_iv).decode('utf-8')

                if current_user.mfa_secret and current_user.mfa_secret_iv:
                    mfa_secret_iv = base64.b64decode(current_user.mfa_secret_iv)
                    encrypted_mfa_secret = base64.b64decode(current_user.mfa_secret)
                    decrypted_mfa_secret = current_aesgcm.decrypt(mfa_secret_iv, encrypted_mfa_secret, None)

                    new_mfa_secret_iv = os.urandom(12)
                    new_encrypted_mfa_secret = new_aesgcm.encrypt(new_mfa_secret_iv, decrypted_mfa_secret, None)

                    current_user.mfa_secret = base64.b64encode(new_encrypted_mfa_secret).decode('utf-8')
                    current_user.mfa_secret_iv = base64.b64encode(new_mfa_secret_iv).decode('utf-8')

                portfolios = user_session.query(Portfolio).filter(Portfolio.user_id == current_user.user_id).all()

                for portfolio in portfolios:
                    portfolio_name_iv = base64.b64decode(portfolio.portfolio_name_iv)
                    encrypted_portfolio_name = base64.b64decode(portfolio.portfolio_name)
                    decrypted_portfolio_name = current_aesgcm.decrypt(portfolio_name_iv, encrypted_portfolio_name, None)

                    new_portfolio_name_iv = os.urandom(12)
                    new_encrypted_portfolio_name = new_aesgcm.encrypt(new_portfolio_name_iv, decrypted_portfolio_name,
                                                                      None)

                    portfolio.portfolio_name = base64.b64encode(new_encrypted_portfolio_name).decode('utf-8')
                    portfolio.portfolio_name_iv = base64.b64encode(new_portfolio_name_iv).decode('utf-8')

                    total_value_iv = base64.b64decode(portfolio.total_value_iv)
                    encrypted_total_value = base64.b64decode(portfolio.total_value)
                    decrypted_total_value = current_aesgcm.decrypt(total_value_iv, encrypted_total_value, None)

                    new_total_value_iv = os.urandom(12)
                    new_encrypted_total_value = new_aesgcm.encrypt(new_total_value_iv, decrypted_total_value, None)

                    portfolio.total_value = base64.b64encode(new_encrypted_total_value).decode('utf-8')
                    portfolio.total_value_iv = base64.b64encode(new_total_value_iv).decode('utf-8')

                transactions = user_session.query(Transaction).filter(Transaction.user_id == current_user.user_id).all()

                for transaction in transactions:
                    amount_iv = base64.b64decode(transaction.amount_iv)
                    encrypted_amount = base64.b64decode(transaction.amount)
                    decrypted_amount = current_aesgcm.decrypt(amount_iv, encrypted_amount, None)

                    new_amount_iv = os.urandom(12)
                    new_encrypted_amount = new_aesgcm.encrypt(new_amount_iv, decrypted_amount, None)

                    transaction.amount = base64.b64encode(new_encrypted_amount).decode('utf-8')
                    transaction.amount_iv = base64.b64encode(new_amount_iv).decode('utf-8')

                    if transaction.description and transaction.description_iv:
                        description_iv = base64.b64decode(transaction.description_iv)
                        encrypted_description = base64.b64decode(transaction.description)
                        decrypted_description = current_aesgcm.decrypt(description_iv, encrypted_description, None)

                        new_description_iv = os.urandom(12)
                        new_encrypted_description = new_aesgcm.encrypt(new_description_iv, decrypted_description, None)

                        transaction.description = base64.b64encode(new_encrypted_description).decode('utf-8')
                        transaction.description_iv = base64.b64encode(new_description_iv).decode('utf-8')

                user_session.delete(active_key)

                new_sym_key = UserSymmetricKeys(
                    user_id=current_user.user_id,
                    encrypted_dek=base64.b64encode(new_encrypted_dek).decode('utf-8'),
                    dek_iv=base64.b64encode(new_dek_iv).decode('utf-8'),
                    created_at=datetime.datetime.now(),
                    active=True
                )
                user_session.add(new_sym_key)

                user_session.commit()

                rotated_count += 1
                print(f" Successfully rotated keys for {current_user.username}")

                full_name = "Unknown User"
                try:
                    full_name = decrypted_full_name.decode('utf-8')
                except (AttributeError, UnicodeDecodeError):
                    full_name = decrypted_full_name

                audit_messages.append(
                    f"The administrator '{admin_full_name}' has rotated the symmetric encryption keys for user '{full_name}'.")

            except Exception as e:
                user_session.rollback()
                failed_count += 1
                print(f"  Error rotating keys for {user.username}: {e}")

                audit_messages.append(
                    f"The administrator '{admin_full_name}' couldn't rotate the symmetric encryption keys for {user.username} due to an error: {e}.")
            finally:
                user_session.close()

        try:
            for msg in audit_messages:
                log_audit(admin_id, "Symmetric Keys Rotation", msg, main_session)

        except Exception as e:
            print(f"Error logging audit messages: {e}")

        print("-" * 200)
        print(f"Key rotation complete. Successfully rotated keys for {rotated_count} users.")

        if failed_count > 0:
            print(f"Failed to rotate keys for {failed_count} users. Check the logs for details.")

    except Exception as e:
        main_session.rollback()
        print(f"Error during key rotation: {e}")
    finally:
        main_session.close()

def rotate_asymmetric_keys(admin_id, admin_full_name):
    print("-" * 200)
    print("Asymmetric Key Rotations")
    print("-" * 200)
    print("WARNING: This will generate new asymmetric keys for all the advisors and clients in the system.")
    confirm = input("Are you sure you want to proceed? (y/n): ")

    if confirm.lower() != 'y':
        print("Asymmetric key rotation cancelled.")
        return

    session = Session()
    try:
        users = session.query(User).filter(User.role != "admin").all()

        if not users:
            print("No users found in the system.")
            return

        master_passphrase = get_master_key()
        master_salt = hashlib.sha256(master_passphrase).digest()[:16]
        key_material = low_level.hash_secret_raw(
            secret=master_passphrase,
            salt=master_salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=64,
            type=low_level.Type.ID
        )
        master_encryption_key = key_material[:32]
        master_aesgcm = AESGCM(master_encryption_key)

        rotation_results = {}
        audit_messages = []

        for user in users:
            try:
                username = user.username
                decrypted_full_name = f"User ID {user.user_id}"

                try:
                    sym_key = session.query(UserSymmetricKeys).filter(
                        UserSymmetricKeys.user_id == user.user_id,
                        UserSymmetricKeys.active == True
                    ).first()

                    if sym_key:
                        dek_iv = base64.b64decode(sym_key.dek_iv)
                        encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
                        user_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

                        user_aesgcm = AESGCM(user_dek)

                        if user.full_name and user.full_name_iv:
                            full_name_iv = base64.b64decode(user.full_name_iv)
                            encrypted_full_name = base64.b64decode(user.full_name)
                            decrypted_full_name = user_aesgcm.decrypt(
                                full_name_iv,
                                encrypted_full_name,
                                None
                            ).decode('utf-8')
                except Exception as e:
                    # If decryption fails, log it but continue with the default name
                    print(f"Warning: Could not decrypt full name for user {user.user_id}: {e}")

                print(f"Rotating keys for user: {username}...")
                new_key = generate_asymmetric_key_pair(user.user_id, session)
                rotation_results[user.user_id] = True if new_key else False

                audit_messages.append(
                    f"The administrator '{admin_full_name}' has rotated the asymmetric encryption keys for user '{decrypted_full_name}'."
                )
                print(f"Successfully rotated asymmetric keys for {username}")

            except Exception as e:
                rotation_results[user.user_id] = False
                session.rollback()
                audit_messages.append(
                    f"The administrator '{admin_full_name}' couldn't rotate the asymmetric encryption keys for user '{username}' due to an error: {e}."
                )
                print(f"Error rotating asymmetric keys for user ID {user.user_id}: {e}")

        for message in audit_messages:
            log_audit(admin_id, "Asymmetric Keys Rotation", message, session)

        session.commit()
        print(f"Completed asymmetric key rotation for {len(users)} users.")
        print(f"Successful: {sum(1 for success in rotation_results.values() if success)}")
        print(f"Failed: {sum(1 for success in rotation_results.values() if not success)}")

        return rotation_results

    except Exception as e:
        session.rollback()
        print(f"Error during asymmetric key rotation: {e}")
        return None
    finally:
        session.close()

def key_management_menu(admin_id, admin_full_name):
    while True:
        clear_screen()
        print("-" * 200)
        print("MyFinance Inc. Key Management")
        print("-" * 200)
        print("- Enter '1' to rotate TLS certificates.")
        print("- Enter '2' to rotate symmetric encryption keys.")
        print("- Enter '3' to rotate asymmetric encryption keys.")
        print("- Enter '4' to create master key backup shares.")
        print("- Enter '5' to recover master key from shares.")
        print("- Enter '6' to return to admin menu.")

        choice = input("\nSelect: ")

        if choice == "1":
            clear_screen()
            rotate_certificates(admin_id, admin_full_name)
            input("\nHit Enter to continue.")
        elif choice == "2":
            clear_screen()
            rotate_symmetric_keys(admin_id, admin_full_name)
            input("\nHit Enter to continue.")
        elif choice == "3":
            clear_screen()
            rotate_asymmetric_keys(admin_id, admin_full_name)
            input("\nHit Enter to continue.")
        elif choice == "4":
            clear_screen()
            session = Session()
            backup_master_key(admin_id, admin_full_name, session)
            session.close()
        elif choice == "5":
            clear_screen()
            session = Session()
            recover_master_key(admin_id, admin_full_name, session)
            session.close()
        elif choice == "6":
            break
        else:
            print("Invalid option. Please try again.")
            input("\nHit Enter to continue.")
