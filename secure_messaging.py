from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import hashlib
import datetime
from models import User, Message, UserAsymmetricKeys
from argon2 import low_level
from pathlib import Path
import secrets

def log_audit(user_id, action, description, session):
    try:
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

        description_iv = os.urandom(12)
        encrypted_description = master_aesgcm.encrypt(
            description_iv,
            description.encode(),
            None
        )

        from models import Logs
        new_log = Logs(
            user_id=user_id,
            action=action,
            description=base64.b64encode(encrypted_description).decode('utf-8'),
            description_iv=base64.b64encode(description_iv).decode('utf-8')
        )

        session.add(new_log)
        session.commit()
        return True
    except Exception as e:
        print(f"Error logging audit event: {e}")
        session.rollback()
        return False

def get_master_key():
    key_path = Path("hardware_security_module") / ("master_key") / ("master.key")

    if key_path.exists():
        with open(key_path, 'rb') as key_file:
            return key_file.read()
    else:
        return "default_master_key".encode()

def generate_asymmetric_key_pair(user_id, session):
    try:
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

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        symmetric_key_iv = os.urandom(12)

        encrypted_private_key = master_aesgcm.encrypt(
            symmetric_key_iv,
            private_key_bytes,
            None
        )

        key_version = session.query(UserAsymmetricKeys).filter(
            UserAsymmetricKeys.user_id == user_id
        ).count() + 1

        previous_active_keys = session.query(UserAsymmetricKeys).filter(
            UserAsymmetricKeys.user_id == user_id,
            UserAsymmetricKeys.is_active == True
        ).all()

        for old_key in previous_active_keys:
            old_key.is_active = False

        new_asymmetric_key = UserAsymmetricKeys(
            user_id=user_id,
            public_key=public_key_bytes,  # Storing as bytes, not str
            private_key_encrypted=base64.b64encode(encrypted_private_key),  # Base64 encode binary data
            private_key_iv=base64.b64encode(symmetric_key_iv).decode('utf-8'),
            key_version=key_version,
            is_active=True,
            created_at=datetime.datetime.now()
        )

        session.add(new_asymmetric_key)
        session.commit()

        return new_asymmetric_key
    except Exception as e:
        session.rollback()
        print(f"Error generating asymmetric key pair: {e}")
        return None

def send_secure_message(sender_id, recipient_id, message_text, session):
    try:
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

        nonce = secrets.token_hex(16)

        sender_active_key = session.query(UserAsymmetricKeys).filter(
            UserAsymmetricKeys.user_id == sender_id,
            UserAsymmetricKeys.is_active == True
        ).first()

        recipient_active_key = session.query(UserAsymmetricKeys).filter(
            UserAsymmetricKeys.user_id == recipient_id,
            UserAsymmetricKeys.is_active == True
        ).first()

        if not sender_active_key:
            sender_active_key = generate_asymmetric_key_pair(sender_id, session)
            if not sender_active_key:
                return None

        if not recipient_active_key:
            recipient_active_key = generate_asymmetric_key_pair(recipient_id, session)
            if not recipient_active_key:
                return None

        symmetric_key = os.urandom(32)
        message_iv = os.urandom(12)

        aesgcm = AESGCM(symmetric_key)
        encrypted_message = aesgcm.encrypt(
            message_iv,
            message_text.encode(),
            None
        )

        recipient_public_key = serialization.load_pem_public_key(recipient_active_key.public_key)

        encrypted_symmetric_key = recipient_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        sender_private_key_encrypted = base64.b64decode(sender_active_key.private_key_encrypted)
        sender_private_key_iv = base64.b64decode(sender_active_key.private_key_iv)

        decrypted_private_key = master_aesgcm.decrypt(
            sender_private_key_iv,
            sender_private_key_encrypted,
            None
        )

        sender_private_key = serialization.load_pem_private_key(
            decrypted_private_key,
            password=None
        )

        message_digest = hashlib.sha256(encrypted_message + nonce.encode()).digest()
        signature = sender_private_key.sign(
            message_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        new_message = Message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            sender_key_id=sender_active_key.key_id,
            recipient_key_id=recipient_active_key.key_id,
            encrypted_message=base64.b64encode(encrypted_message).decode('utf-8'),
            message_iv=base64.b64encode(message_iv).decode('utf-8'),
            encrypted_symmetric_key=base64.b64encode(encrypted_symmetric_key).decode('utf-8'),
            signature=base64.b64encode(signature).decode('utf-8'),
            nonce=nonce,
            is_read=False,
            timestamp=datetime.datetime.now()
        )

        session.add(new_message)
        session.commit()

        return new_message
    except Exception as e:
        session.rollback()
        print(f"Error sending secure message: {e}")
        return None

def read_secure_message(message_id, recipient_id, session):
    try:
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

        message = session.query(Message).filter(
            Message.message_id == message_id,
            Message.recipient_id == recipient_id
        ).first()

        if not message:
            print("Message not found or unauthorised access.")
            return None

        existing_nonce = session.query(Message).filter(
            Message.nonce == message.nonce,
            Message.is_read == True,
            Message.message_id != message_id
        ).first()

        if existing_nonce:
            raise ValueError("Replay attack detected: Nonce already used in a different message")

        recipient_key = session.query(UserAsymmetricKeys).filter(
            UserAsymmetricKeys.key_id == message.recipient_key_id
        ).first()

        if not recipient_key:
            print("Recipient key not found.")
            return None

        sender_key = session.query(UserAsymmetricKeys).filter(
            UserAsymmetricKeys.key_id == message.sender_key_id
        ).first()

        if not sender_key:
            print("Sender key not found for signature verification.")
            return None

        encrypted_message = base64.b64decode(message.encrypted_message)
        message_iv = base64.b64decode(message.message_iv)
        encrypted_symmetric_key = base64.b64decode(message.encrypted_symmetric_key)
        signature = base64.b64decode(message.signature)
        nonce = message.nonce

        private_key_encrypted = base64.b64decode(recipient_key.private_key_encrypted)
        private_key_iv = base64.b64decode(recipient_key.private_key_iv)

        decrypted_private_key_bytes = master_aesgcm.decrypt(
            private_key_iv,
            private_key_encrypted,
            None
        )

        recipient_private_key = serialization.load_pem_private_key(
            decrypted_private_key_bytes,
            password=None
        )

        symmetric_key = recipient_private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        sender_public_key = serialization.load_pem_public_key(sender_key.public_key)
        message_digest = hashlib.sha256(encrypted_message + nonce.encode()).digest()

        try:
            sender_public_key.verify(
                signature,
                message_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            print(f"Signature verification failed: {e}")
            log_audit(recipient_id, "Security Alert", f"Signature verification failed for message {message_id}", session)
            return "SIGNATURE VERIFICATION FAILED - Message may have been tampered with!"

        decrypted_message = AESGCM(symmetric_key).decrypt(
            message_iv,
            encrypted_message,
            None
        ).decode()

        if not message.is_read:
            message.is_read = True
            session.commit()

        return decrypted_message
    except Exception as e:
        session.rollback()
        print(f"Error reading secure message: {e}")
        return None
def list_messages(user_id, session, sent=False):
    try:
        if sent:
            messages = session.query(Message).filter(Message.sender_id == user_id).all()
        else:
            messages = session.query(Message).filter(Message.recipient_id == user_id).all()

        return messages
    except Exception as e:
        print(f"Error listing messages: {e}")
        return []

def message_menu(user_id, user_full_name, role, session):
    try:
        while True:
            print("-" * 200)
            print("Secure Messaging System")
            print("-" * 200)
            print("- Enter '1' to send a new message")
            print("- Enter '2' to view received messages")
            print("- Enter '3' to view sent messages")
            print("- Enter '4' to return to main menu")

            choice = input("\nSelect an option: ")

            if choice == "1":
                print("-" * 200)
                print("Select Recipient")
                print("-" * 200)

                if role == "client":
                    other_role = "advisor"
                    advisors = session.query(User).filter(User.role == "advisor").all()
                    print("Available Financial Advisors:")
                    for advisor in advisors:
                        print(f"User ID: {advisor.user_id} | Name: {advisor.username}")
                else:
                    other_role = "client"
                    clients = session.query(User).filter(User.role == "client").all()
                    print("Available Clients:")
                    for client in clients:
                        print(f"User ID: {client.user_id} | Name: {client.username}")

                try:
                    recipient_id = int(input("\nEnter the user ID of the recipient: "))
                    recipient = session.query(User).filter(User.user_id == recipient_id).first()

                    if not recipient:
                        print("Recipient not found.")
                        input("\nHit Enter to continue.")
                        continue

                    message_text = input("Enter your message: ")

                    if not message_text.strip():
                        print("Message cannot be empty.")
                        input("\nHit Enter to continue.")
                        continue

                    new_message = send_secure_message(user_id, recipient_id, message_text, session)

                    if new_message:
                        log_audit(user_id, "Sent Message", f"The {role} '{user_full_name}' send a message to a {other_role}.", session)
                        print("Message sent successfully!")
                    else:
                        log_audit(user_id, "Sent Message", f"The {role} '{user_full_name}' failed to send a message to a {other_role}.", session)
                        print("Failed to send message.")

                except ValueError:
                    print("Invalid input. Please enter a valid recipient ID.")

                input("\nHit Enter to continue.")

            elif choice == "2":
                print("-" * 200)
                print("Received Messages")
                print("-" * 200)

                received_messages = list_messages(user_id, session, sent=False)

                if not received_messages:
                    print("No messages found.")
                else:
                    if role == "client":
                        other_role = "advisor"
                    else:
                        other_role = "client"

                    print(f"{'ID':<6} {'From':<15} {'Date':<20} {'Status':<10}")
                    print("-" * 200)

                    for msg in received_messages:
                        sender = session.query(User).filter(User.user_id == msg.sender_id).first()
                        sender_name = sender.username if sender else "Unknown"
                        date = msg.timestamp.strftime('%d %b %Y, %H:%M') if hasattr(msg, 'timestamp') else "N/A"
                        status = "Read" if msg.is_read else "Unread"

                        print(f"{msg.message_id:<6} {sender_name:<15} {date:<20} {status:<10}")

                    try:
                        message_id = input("\nEnter message ID to read: ")
                        if message_id:
                            message_id = int(message_id)
                            decrypted_message = read_secure_message(message_id, user_id, session)

                            if decrypted_message:
                                print("\n ========================================  Message Content ========================================  ")
                                print(decrypted_message)
                                log_audit(user_id, "Viewed Message",
                                          f"The {role} '{user_full_name}' viewed a message from a {other_role}.", session)
                            else:
                                log_audit(user_id, "Viewed Message",
                                          f"The {role} '{user_full_name}' could not view a message from a {other_role}.",
                                          session)
                                print("Could not read message.")
                    except ValueError:
                        print("Invalid message ID.")

                input("\nHit Enter to continue.")

            elif choice == "3":
                print("-" * 200)
                print("Sent Messages")
                print("-" * 200)

                sent_messages = list_messages(user_id, session, sent=True)

                if not sent_messages:
                    print("No sent messages found.")
                else:
                    log_audit(user_id, "Viewed Message",
                              f"The {role} '{user_full_name}' viewed their sent messages.",
                              session)

                    print(f"{'ID':<6} {'To':<15} {'Date':<20} {'Status':<10}")
                    print("-" * 200)

                    for msg in sent_messages:
                        recipient = session.query(User).filter(User.user_id == msg.recipient_id).first()
                        recipient_name = recipient.username if recipient else "Unknown"
                        date = msg.timestamp.strftime('%d %b %Y, %H:%M') if hasattr(msg, 'timestamp') else "N/A"
                        status = "Read" if msg.is_read else "Unread"

                        print(f"{msg.message_id:<6} {recipient_name:<15} {date:<20} {status:<10}")

                input("\nHit Enter to continue.")

            elif choice == "4":
                break
            else:
                print("Invalid option. Please try again.")
                input("\nHit Enter to continue.")

    except Exception as e:
        print(f"Error in message menu: {e}")
        input("\nHit Enter to continue.")
    finally:
        pass