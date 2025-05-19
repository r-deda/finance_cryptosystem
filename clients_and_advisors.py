from __init__ import *
import sys
from models import User, Portfolio, Transaction, UserSymmetricKeys, Logs
from __init__ import log_audit
import os
import base64
import datetime
from sqlalchemy import create_engine, or_
from sqlalchemy.orm import sessionmaker
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from argon2 import low_level, PasswordHasher
import hashlib
import json

engine = create_engine('sqlite:///myfinance.db')
Session = sessionmaker(bind=engine)

def log_audit(user_id, action, description):
    session = Session()
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
    
def view_portfolios(user_id):
    session = Session()
    try:
        user = session.query(User).filter(User.user_id == user_id).first()
        if not user:
            print("User not found.")
            return

        master_passphrase = get_master_key()
        salt = hashlib.sha256(master_passphrase).digest()[:16]
        key_material = low_level.hash_secret_raw(secret=master_passphrase, salt=salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=64, type=low_level.Type.ID)

        master_encryption_key = key_material[:32]

        sym_key = session.query(UserSymmetricKeys).filter(
            UserSymmetricKeys.user_id == user_id,
            UserSymmetricKeys.active == True
        ).first()

        if not sym_key:
            print("Error: Could not retrieve encryption keys")
            return

        master_aesgcm = AESGCM(master_encryption_key)
        dek_iv = base64.b64decode(sym_key.dek_iv)
        encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
        user_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

        user_aesgcm = AESGCM(user_dek)
        portfolios = session.query(Portfolio).filter(Portfolio.user_id == user_id).all()

        if not portfolios:
            print("You don't have any portfolios yet.")
            return

        print("-" * 200)
        print("Your Portfolios:")
        print("-" * 200)

        for portfolio in portfolios:
            portfolio_name_iv = base64.b64decode(portfolio.portfolio_name_iv)
            encrypted_portfolio_name = base64.b64decode(portfolio.portfolio_name)
            decrypted_name = user_aesgcm.decrypt(portfolio_name_iv, encrypted_portfolio_name, None).decode('utf-8')

            total_value_iv = base64.b64decode(portfolio.total_value_iv)
            encrypted_total_value = base64.b64decode(portfolio.total_value)
            decrypted_value = user_aesgcm.decrypt(total_value_iv, encrypted_total_value, None).decode('utf-8')

            print(f"Portfolio ID: {portfolio.portfolio_id} | Name: {decrypted_name} | Total Value: £{decrypted_value} | Created: {portfolio.created_at.strftime('%d %B %Y, %H:%M')}")

    except Exception as e:
        print(f"Error viewing portfolios: {e}")
    finally:
        session.close()

def create_portfolio(user_id):
    session = Session()
    try:
        master_passphrase = get_master_key()
        salt = hashlib.sha256(master_passphrase).digest()[:16]
        key_material = low_level.hash_secret_raw(secret=master_passphrase, salt=salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=64, type=low_level.Type.ID)

        master_encryption_key = key_material[:32]
        sym_key = session.query(UserSymmetricKeys).filter(
            UserSymmetricKeys.user_id == user_id,
            UserSymmetricKeys.active == True
        ).first()

        if not sym_key:
            print("Error: Could not retrieve encryption keys")
            return

        master_aesgcm = AESGCM(master_encryption_key)
        dek_iv = base64.b64decode(sym_key.dek_iv)
        encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
        user_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

        user_aesgcm = AESGCM(user_dek)

        print("-" * 200)
        print("Create Your Portfolio")
        print("-" * 200)

        portfolio_name = input("Enter portfolio name: ")

        while True:
            try:
                initial_value = float(input("Enter initial value: £"))
                if initial_value < 0:
                    print("Value cannot be negative. Please try again.")
                    continue
                break
            except ValueError:
                print("Please enter a valid number.")

        portfolio_name_iv = os.urandom(12)
        encrypted_portfolio_name = user_aesgcm.encrypt(portfolio_name_iv, portfolio_name.encode(), None)

        total_value_iv = os.urandom(12)
        encrypted_total_value = user_aesgcm.encrypt(total_value_iv, str(initial_value).encode(), None)

        new_portfolio = Portfolio(
            user_id=user_id,
            portfolio_name=base64.b64encode(encrypted_portfolio_name).decode('utf-8'),
            portfolio_name_iv=base64.b64encode(portfolio_name_iv).decode('utf-8'),
            total_value=base64.b64encode(encrypted_total_value).decode('utf-8'),
            total_value_iv=base64.b64encode(total_value_iv).decode('utf-8'),
            created_at=datetime.datetime.now()
        )

        session.add(new_portfolio)
        session.commit()

        print(f"\nPortfolio '{portfolio_name}' created successfully with initial value of £{initial_value:.2f}")

    except Exception as e:
        session.rollback()
        print(f"Error creating portfolio: {e}")
    finally:
        session.close()

def transfer_between_portfolios(user_id, user_full_name, role):
    session = Session()
    try:
        user = session.query(User).filter(User.user_id == user_id).first()
        if not user:
            print("User not found.")
            return

        portfolios = session.query(Portfolio).filter(Portfolio.user_id == user_id).all()

        if not portfolios:
            print("This user doesn't have any portfolios. Please create a portfolio first.")
            return

        if len(portfolios) < 2:
            print("This user needs at least two portfolios to transfer money. Please create another portfolio.")
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
        hmac_key = key_material[32:]

        sym_key = session.query(UserSymmetricKeys).filter(
            UserSymmetricKeys.user_id == user_id,
            UserSymmetricKeys.active == True
        ).first()

        master_aesgcm = AESGCM(master_encryption_key)
        dek_iv = base64.b64decode(sym_key.dek_iv)
        encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
        user_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

        user_aesgcm = AESGCM(user_dek)

        full_name_iv = base64.b64decode(user.full_name_iv)
        encrypted_full_name = base64.b64decode(user.full_name)
        current_full_name = user_aesgcm.decrypt(full_name_iv, encrypted_full_name, None).decode('utf-8')

        print(f"{current_full_name}'s portfolios:\n")

        portfolio_map = {}
        for idx, portfolio in enumerate(portfolios, 1):
            name_iv = base64.b64decode(portfolio.portfolio_name_iv)
            encrypted_name = base64.b64decode(portfolio.portfolio_name)
            decrypted_name = user_aesgcm.decrypt(name_iv, encrypted_name, None).decode('utf-8')

            value_iv = base64.b64decode(portfolio.total_value_iv)
            encrypted_value = base64.b64decode(portfolio.total_value)
            decrypted_value = user_aesgcm.decrypt(value_iv, encrypted_value, None).decode('utf-8')

            print(f"Portfolio ID: {idx} | Name: {decrypted_name} | Total Value: £{decrypted_value}")
            portfolio_map[idx] = {
                "id": portfolio.portfolio_id,
                "name": decrypted_name,
                "value": float(decrypted_value)
            }

        while True:
            try:
                source_choice = int(input("\nSelect the Source Portfolio's ID: "))
                if source_choice not in portfolio_map:
                    print("Invalid choice. Please select a valid portfolio number.")
                    continue
                break
            except ValueError:
                print("Please enter a valid number.")

        source_portfolio = portfolio_map[source_choice]

        while True:
            try:
                dest_choice = int(input("Select the Destination Portfolio's ID: "))
                if dest_choice not in portfolio_map:
                    print("Invalid choice. Please select a valid portfolio number.")
                    continue

                if dest_choice == source_choice:
                    print("Source and destination portfolios cannot be the same.")
                    continue

                break
            except ValueError:
                print("Please enter a valid number.")

        destination_portfolio = portfolio_map[dest_choice]

        while True:
            try:
                transfer_amount = float(input(f"\nPlease Select Amount to Transfer: £"))
                if transfer_amount <= 0:
                    print("Amount must be greater than zero.")
                    continue

                if transfer_amount > source_portfolio['value']:
                    print(f"Insufficient funds. {source_portfolio['name']} only has £{source_portfolio['value']}.")
                    continue

                break
            except ValueError:
                print("Please enter a valid number.")

        description = input("Enter a Description/Reference (Optional): ")

        nonce = secrets.token_bytes(16)
        nonce_base64 = base64.b64encode(nonce).decode('utf-8')

        transaction_data = {
            'source_portfolio_id': source_portfolio['id'],
            'destination_portfolio_id': destination_portfolio['id'],
            'amount': transfer_amount,
            'timestamp': datetime.datetime.now().isoformat(),
            'nonce': nonce_base64
        }

        sorted_data = json.dumps(transaction_data, sort_keys=True)

        h = hmac.HMAC(
            key=hmac_key,
            algorithm=hashes.SHA256()
        )
        h.update(sorted_data.encode('utf-8'))
        hmac_signature = base64.b64encode(h.finalize()).decode('utf-8')

        source_db_portfolio = session.query(Portfolio).filter(Portfolio.portfolio_id == source_portfolio['id']).first()
        new_source_value = source_portfolio['value'] - transfer_amount

        source_iv = os.urandom(12)
        source_encrypted_value = user_aesgcm.encrypt(source_iv, str(new_source_value).encode(), None)
        source_db_portfolio.total_value = base64.b64encode(source_encrypted_value).decode('utf-8')
        source_db_portfolio.total_value_iv = base64.b64encode(source_iv).decode('utf-8')

        dest_db_portfolio = session.query(Portfolio).filter(Portfolio.portfolio_id == destination_portfolio['id']).first()
        new_dest_value = destination_portfolio['value'] + transfer_amount

        dest_iv = os.urandom(12)
        dest_encrypted_value = user_aesgcm.encrypt(dest_iv, str(new_dest_value).encode(), None)
        dest_db_portfolio.total_value = base64.b64encode(dest_encrypted_value).decode('utf-8')
        dest_db_portfolio.total_value_iv = base64.b64encode(dest_iv).decode('utf-8')

        amount_iv = os.urandom(12)
        encrypted_amount = user_aesgcm.encrypt(amount_iv, str(transfer_amount).encode(), None)

        description_iv = None
        encrypted_description = None

        if description:
            description_iv = os.urandom(12)
            encrypted_description = user_aesgcm.encrypt(description_iv, description.encode(), None)

        transaction = Transaction(
            amount=base64.b64encode(encrypted_amount).decode('utf-8'),
            amount_iv=base64.b64encode(amount_iv).decode('utf-8'),
            description=base64.b64encode(encrypted_description).decode('utf-8') if description else None,
            description_iv=base64.b64encode(description_iv).decode('utf-8') if description_iv else None,
            user_id=user_id,
            source_portfolio_id=source_portfolio['id'],
            destination_portfolio_id=destination_portfolio['id'],
            initiated_by=role,
            nonce=nonce_base64,
            hmac_signature=hmac_signature,
            timestamp=datetime.datetime.now()
        )

        session.add(transaction)
        session.commit()

        log_audit(user_id, "Portfolio Transfer",
                  f"The {role} '{user_full_name}>' has transferred money between two portfolios.")

        print("-" * 200)
        print(f"Transfer complete! £{transfer_amount:.2f} transferred from {source_portfolio['name']} to {destination_portfolio['name']}.")
        print(f"New balance for {source_portfolio['name']}: £{new_source_value:.2f}")
        print(f"New balance for {destination_portfolio['name']}: £{new_dest_value:.2f}")
        print(f"This transaction was initiated by a {role}")
        print("-" * 200)

    except Exception as e:
        session.rollback()
        print(f"Error during transfer: {e}")
    finally:
        session.close()

def view_transaction_history(user_id):
    session = Session()
    try:
        user = session.query(User).filter(User.user_id == user_id).first()
        if not user:
            print("User not found.")
            return

        master_passphrase = get_master_key()
        deterministic_salt = hashlib.sha256(master_passphrase).digest()[:16]
        key_material = low_level.hash_secret_raw(
            secret=master_passphrase,
            salt=deterministic_salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=64,
            type=low_level.Type.ID
        )
        master_encryption_key = key_material[:32]

        sym_key = session.query(UserSymmetricKeys).filter(
            UserSymmetricKeys.user_id == user_id,
            UserSymmetricKeys.active == True
        ).first()

        if not sym_key:
            print("Error: Could not retrieve encryption keys")
            return

        master_aesgcm = AESGCM(master_encryption_key)
        dek_iv = base64.b64decode(sym_key.dek_iv)
        encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
        user_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

        user_aesgcm = AESGCM(user_dek)

        portfolios = {}
        user_portfolios = session.query(Portfolio).filter(Portfolio.user_id == user_id).all()

        for portfolio in user_portfolios:
            portfolio_name_iv = base64.b64decode(portfolio.portfolio_name_iv)
            encrypted_portfolio_name = base64.b64decode(portfolio.portfolio_name)
            decrypted_name = user_aesgcm.decrypt(portfolio_name_iv, encrypted_portfolio_name, None).decode('utf-8')
            portfolios[portfolio.portfolio_id] = decrypted_name

        transactions = session.query(Transaction).filter(
            or_(
                Transaction.source_portfolio_id.in_(portfolios.keys()),
                Transaction.destination_portfolio_id.in_(portfolios.keys())
            )
        ).order_by(Transaction.timestamp.desc()).all()

        if not transactions:
            print("No transaction history found.")
            return

        full_name_iv = base64.b64decode(user.full_name_iv)
        encrypted_full_name = base64.b64decode(user.full_name)
        current_full_name = user_aesgcm.decrypt(full_name_iv, encrypted_full_name, None).decode('utf-8')

        print("-" * 200)
        print(current_full_name + "'s Transaction History:")
        print("-" * 200)
        print(f"{'ID':<5} {'Date':<20} {'Amount':<12} {'From/To':<30} {'Initiator':<15} {'Description':<20}")
        print("-" * 200)

        for transaction in transactions:
            amount_iv = base64.b64decode(transaction.amount_iv)
            encrypted_amount = base64.b64decode(transaction.amount)
            amount = user_aesgcm.decrypt(amount_iv, encrypted_amount, None).decode('utf-8')
            from_to = f"{portfolios.get(transaction.source_portfolio_id, 'Unknown')} → {portfolios.get(transaction.destination_portfolio_id, 'Unknown')}"
            description = ""
            if transaction.description and transaction.description_iv:
                try:
                    description_iv = base64.b64decode(transaction.description_iv)
                    encrypted_description = base64.b64decode(transaction.description)
                    description = user_aesgcm.decrypt(description_iv, encrypted_description, None).decode('utf-8')
                except:
                    description = "Encrypted description"

            formatted_date = transaction.timestamp.strftime('%d %b %Y, %H:%M')

            initiated_by = getattr(transaction, 'initiated_by', 'client')

            print(
                f"{transaction.transaction_id:<5} {formatted_date:<20} £{float(amount):<10.2f} {from_to:<30} {initiated_by:<15} {description:<20}")

        print("-" * 200)
        print("All transactions have HMAC signatures and nonces to verify integrity and authenticity.")
        print("-" * 200)
    except Exception as e:
        print(f"Error viewing transaction history: {e}")
    finally:
        session.close()

def edit_user_profile(user_id, user_full_name):
    session = Session()
    try:
        user = session.query(User).filter(User.user_id == user_id).first()
        if not user:
            print("User not found.")
            return

        master_passphrase = get_master_key()
        deterministic_salt = hashlib.sha256(master_passphrase).digest()[:16]
        key_material = low_level.hash_secret_raw(
            secret=master_passphrase,
            salt=deterministic_salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=64,
            type=low_level.Type.ID
        )
        master_encryption_key = key_material[:32]

        sym_key = session.query(UserSymmetricKeys).filter(
            UserSymmetricKeys.user_id == user_id,
            UserSymmetricKeys.active == True
        ).first()

        if not sym_key:
            print("Error: Could not retrieve encryption keys")
            return

        master_aesgcm = AESGCM(master_encryption_key)
        dek_iv = base64.b64decode(sym_key.dek_iv)
        encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
        user_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

        user_aesgcm = AESGCM(user_dek)

        try:
            email_iv = base64.b64decode(user.email_iv)
            encrypted_email = base64.b64decode(user.email)
            current_email = user_aesgcm.decrypt(email_iv, encrypted_email, None).decode('utf-8')

            phone_iv = base64.b64decode(user.phone_iv)
            encrypted_phone = base64.b64decode(user.phone)
            current_phone = user_aesgcm.decrypt(phone_iv, encrypted_phone, None).decode('utf-8')

            full_name_iv = base64.b64decode(user.full_name_iv)
            encrypted_full_name = base64.b64decode(user.full_name)
            current_full_name = user_aesgcm.decrypt(full_name_iv, encrypted_full_name, None).decode('utf-8')
        except Exception as e:
            print(f"Error decrypting user data: {e}")
            return

        profile_result = profile_menu(user_id, user, user_aesgcm, current_email, current_phone, current_full_name,
                                      session)

        session.commit()
        print("All profile changes have been saved successfully.")

    except Exception as e:
        session.rollback()
        print(f"Error editing profile: {e}")
        import traceback
        traceback.print_exc()
    finally:
        session.close()

def profile_menu(user_id, user, user_aesgcm, current_email, current_phone, current_full_name, session):
    edit_complete = False

    while not edit_complete:
        print("-" * 200)
        print("Your Profile")
        print("-" * 200)
        print(f"Username: {user.username} (cannot be changed)")
        print(f"Current Email: {current_email}")
        print(f"Current Phone: {current_phone}")
        print(f"Current Full Name: {current_full_name}")
        print("-" * 200)
        print("What would you like to change?")
        print("- Enter '1' to change your password.")
        print("- Enter '2' to change your email.")
        print("- Enter '3' to change your phone number.")
        print("- Enter '4' to change your full name.")
        print("- Enter '5' to go back to the client menu.")

        choice = input("\nSelect an option: ")

        try:
            if choice == "1":
                change_password(user, session)
                log_audit(user_id, "Change Password", f"The client '{current_full_name}' changed their password.")
            elif choice == "2":
                result = change_email(user, user_aesgcm, session)
                if result is not None:
                    current_email = result
                    log_audit(user_id, "Change Email", f"The client '{current_full_name}' has changed their email.")
            elif choice == "3":
                result = change_phone(user, user_aesgcm, session)
                if result is not None:
                    current_phone = result
                    log_audit(user_id, "Change Phone", f"The client '{current_full_name}' changed their phone number.")
            elif choice == "4":
                result = change_full_name(user, user_aesgcm, session)
                if result is not None:
                    old_full_name = current_full_name
                    current_full_name = result
                    log_audit(user_id, "Change Name", f"The client '{old_full_name}' has now changed their full name to {current_full_name}.")
            elif choice == "5":
                edit_complete = True
                session.close()

        except Exception as e:
            print(f"Error processing request: {e}")
            input("\nHit enter to continue.")

    return {
        'email': current_email,
        'phone': current_phone,
        'full_name': current_full_name
    }

def change_password(user, session):
    try:
        print("-" * 200)
        print("Change Password")
        print("-" * 200)

        try:
            if sys.stdin.isatty():
                print("\nYour password will be masked and won't be visible.")
                current_password = getpass.getpass("Enter current password: ")
            else:
                print("Password masking not available in this environment.")
                current_password = input("Enter current password: ")
        except Exception:
            current_password = input("Enter current password: ")

        ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

        try:
            ph.verify(user.password, current_password)
        except Exception:
            print("Current password is incorrect.")
            return None

        print("\nPassword Requirements:")
        print("- At least 8 characters")
        print("- At least one uppercase letter")
        print("- At least one number")
        print("- At least one special character")

        while True:
            new_password = input("\nEnter your new password: ")
            confirm_password = input("Confirm new password: ")

            if new_password != confirm_password:
                print("Passwords do not match. Please try again.")
                continue

            if (len(new_password) >= 8 and
                    any(c.isupper() for c in new_password) and
                    any(c.isdigit() for c in new_password) and
                    any(c in "!@#$%^&*()-_+=<>?/|{}[]" for c in new_password)):
                break
            else:
                print("Password does not meet requirements. Please try again.")

        password_hash = ph.hash(new_password)
        user.password = password_hash

        print("\nPassword updated successfully!")
        input("\nHit enter to continue.")
        return True

    except Exception as e:
        print(f"\nError changing password: {e}")
        input("\nHit enter to continue.")
        return None

def change_email(user, user_aesgcm, session):
    try:
        print("-" * 200)
        print("Change Email Address")
        print("-" * 200)

        email_iv = base64.b64decode(user.email_iv)
        encrypted_email = base64.b64decode(user.email)
        current_email = user_aesgcm.decrypt(email_iv, encrypted_email, None).decode('utf-8')

        print(f"Current email: {current_email}")

        while True:
            new_email = input("Enter new email address: ")

            if "@" not in new_email or "." not in new_email:
                print("\nInvalid email format. Please try again.")
                continue

            email_exists = False
            all_users = session.query(User).all()

            master_passphrase = get_master_key()
            deterministic_salt = hashlib.sha256(master_passphrase).digest()[:16]
            key_material = low_level.hash_secret_raw(secret=master_passphrase, salt=deterministic_salt,
                                                     time_cost=3, memory_cost=65536, parallelism=4,
                                                     hash_len=64, type=low_level.Type.ID)
            master_encryption_key = key_material[:32]
            master_aesgcm = AESGCM(master_encryption_key)

            for other_user in all_users:
                if other_user.user_id == user.user_id:
                    continue

                try:
                    sym_key = session.query(UserSymmetricKeys).filter(
                        UserSymmetricKeys.user_id == other_user.user_id,
                        UserSymmetricKeys.active == True
                    ).first()

                    if not sym_key:
                        continue

                    dek_iv = base64.b64decode(sym_key.dek_iv)
                    encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
                    other_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

                    other_aesgcm = AESGCM(other_dek)
                    other_email_iv = base64.b64decode(other_user.email_iv)
                    other_encrypted_email = base64.b64decode(other_user.email)
                    other_email = other_aesgcm.decrypt(other_email_iv, other_encrypted_email, None).decode('utf-8')

                    if other_email.lower() == new_email.lower():
                        email_exists = True
                        break
                except Exception:
                    continue

            if email_exists:
                print("\nThis email is already registered. Please use a different email.")
            else:
                break

        new_email_iv = os.urandom(12)
        encrypted_new_email = user_aesgcm.encrypt(new_email_iv, new_email.encode(), None)

        user.email = base64.b64encode(encrypted_new_email).decode('utf-8')
        user.email_iv = base64.b64encode(new_email_iv).decode('utf-8')

        print("\nEmail updated successfully!")
        input("\nHit enter to continue.")
        return new_email

    except Exception as e:
        print(f"Error changing email: {e}")
        input("\nHit enter to continue.")
        return None


def change_phone(user, user_aesgcm, session):
    try:
        print("-" * 200)
        print("Change Phone Number")
        print("-" * 200)

        phone_iv = base64.b64decode(user.phone_iv)
        encrypted_phone = base64.b64decode(user.phone)
        current_phone = user_aesgcm.decrypt(phone_iv, encrypted_phone, None).decode('utf-8')

        print(f"Current phone number: {current_phone}")

        while True:
            try:
                new_phone = input("Enter new phone number: ")

                int(new_phone)

                phone_exists = False
                all_users = session.query(User).all()

                master_passphrase = get_master_key()
                deterministic_salt = hashlib.sha256(master_passphrase).digest()[:16]
                key_material = low_level.hash_secret_raw(secret=master_passphrase, salt=deterministic_salt,
                                                         time_cost=3, memory_cost=65536, parallelism=4,
                                                         hash_len=64, type=low_level.Type.ID)
                master_encryption_key = key_material[:32]
                master_aesgcm = AESGCM(master_encryption_key)

                for other_user in all_users:
                    if other_user.user_id == user.user_id:
                        continue

                    try:
                        sym_key = session.query(UserSymmetricKeys).filter(
                            UserSymmetricKeys.user_id == other_user.user_id,
                            UserSymmetricKeys.active == True
                        ).first()

                        if not sym_key:
                            continue

                        dek_iv = base64.b64decode(sym_key.dek_iv)
                        encrypted_dek = base64.b64decode(sym_key.encrypted_dek)
                        other_dek = master_aesgcm.decrypt(dek_iv, encrypted_dek, None)

                        other_aesgcm = AESGCM(other_dek)
                        other_phone_iv = base64.b64decode(other_user.phone_iv)
                        other_encrypted_phone = base64.b64decode(other_user.phone)
                        other_phone = other_aesgcm.decrypt(other_phone_iv, other_encrypted_phone, None).decode('utf-8')

                        if other_phone == new_phone:
                            phone_exists = True
                            break
                    except Exception:
                        continue

                if phone_exists:
                    print("\nThis phone number is already registered. Please use a different number.")
                else:
                    break

            except ValueError:
                print("\nPhone number should be numeric. Please try again.")

        new_phone_iv = os.urandom(12)
        encrypted_new_phone = user_aesgcm.encrypt(new_phone_iv, new_phone.encode(), None)

        user.phone = base64.b64encode(encrypted_new_phone).decode('utf-8')
        user.phone_iv = base64.b64encode(new_phone_iv).decode('utf-8')

        print("\nPhone number updated successfully!")
        input("\nHit enter to continue.")
        return new_phone

    except Exception as e:
        print(f"\nError changing phone number: {e}")
        input("\nHit enter to continue.")
        return None

def change_full_name(user, user_aesgcm, session):
    try:
        print("-" * 200)
        print("Change Full Name")
        print("-" * 200)

        name_iv = base64.b64decode(user.full_name_iv)
        encrypted_name = base64.b64decode(user.full_name)
        current_name = user_aesgcm.decrypt(name_iv, encrypted_name, None).decode('utf-8')

        print(f"Current full name: {current_name}")
        new_name = input("Enter new full name: ")

        new_name_iv = os.urandom(12)
        encrypted_new_name = user_aesgcm.encrypt(new_name_iv, new_name.encode(), None)

        user.full_name = base64.b64encode(encrypted_new_name).decode('utf-8')
        user.full_name_iv = base64.b64encode(new_name_iv).decode('utf-8')

        print("\nFull name updated successfully!")
        input("\nHit enter to continue.")
        return new_name

    except Exception as e:
        print(f"\nError changing full name: {e}")
        input("\nHit enter to continue.")
        return None
