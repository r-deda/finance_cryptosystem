import os
import base64
import hashlib
import datetime
import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import low_level
from models import Session, Logs
from pathlib import Path

class ShamirSecretSharing:
    def __init__(self, prime=208351617316091241234326746312124448251235562226470491514186331217050270460481):
        self.prime = prime

    def _eval_polynomial(self, poly, x, prime):
        result = 0
        for coeff in reversed(poly):
            result = (result * x + coeff) % prime
        return result

    def _generate_polynomial(self, secret, degree, prime):
        poly = [secret]
        for _ in range(degree):
            poly.append(random.randint(1, prime - 1))
        return poly

    def _mod_inverse(self, k, prime):
        if k == 0:
            raise ZeroDivisionError('Division by zero')

        if k < 0:
            return prime - self._mod_inverse(-k, prime)

        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = prime, k

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        return old_s % prime

    def _lagrange_interpolation(self, x_coords, y_coords, x, prime):
        k = len(x_coords)
        if k != len(y_coords):
            raise ValueError("Number of x and y coordinates must be equal")

        result = 0
        for i in range(k):
            basis = 1
            for j in range(k):
                if i != j:
                    numerator = (x - x_coords[j]) % prime
                    denominator = (x_coords[i] - x_coords[j]) % prime
                    inv = self._mod_inverse(denominator, prime)
                    basis = (basis * numerator * inv) % prime
            result = (result + y_coords[i] * basis) % prime

        return result

    def split_secret(self, secret_bytes, threshold, shares_count):
        if threshold > shares_count:
            raise ValueError("Threshold cannot be greater than the number of shares")

        secret_int = int.from_bytes(secret_bytes, byteorder='big')

        poly = self._generate_polynomial(secret_int, threshold - 1, self.prime)

        shares = []
        for i in range(1, shares_count + 1):
            x = i
            y = self._eval_polynomial(poly, x, self.prime)

            share_data = (x, y)
            shares.append(share_data)

        return shares

    def recover_secret(self, shares, secret_length=32):
        if not shares:
            raise ValueError("No shares provided")

        x_coords = [share[0] for share in shares]
        y_coords = [share[1] for share in shares]

        secret_int = self._lagrange_interpolation(x_coords, y_coords, 0, self.prime)

        try:
            return secret_int.to_bytes(secret_length, byteorder='big')
        except OverflowError:
            raise ValueError(f"Recovered secret is too large for {secret_length} bytes")

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

def backup_master_key(admin_id, admin_full_name, session):
    print("-" * 200)
    print("Master Key Backup - Shamir's Secret Sharing")
    print("-" * 200)
    print("This process will create shares of the master encryption key.")
    print("A specific number of these shares will be required to reconstruct the key.")
    print("WARNING: Store these shares securely in separate locations.")

    confirm = input("Do you want to proceed? (y/n): ")
    if confirm.lower() != 'y':
        print("Master key backup cancelled.")
        return

    try:
        master_passphrase = get_master_key()

        if len(master_passphrase) < 32:
            master_passphrase = master_passphrase.ljust(32, b'\0')
        elif len(master_passphrase) > 32:
            master_passphrase = hashlib.sha256(master_passphrase).digest()

        while True:
            try:
                total_shares = int(input("Enter the total number of shares to create (minimum 2): "))
                if total_shares < 2:
                    print("You must create at least 2 shares.")
                    continue

                threshold = int(input(f"Enter the minimum shares needed to reconstruct the key (2-{total_shares}): "))
                if threshold < 2 or threshold > total_shares:
                    print(f"Threshold must be between 2 and {total_shares}.")
                    continue

                break
            except ValueError:
                print("Please enter valid numbers.")

        shamir = ShamirSecretSharing()
        shares = shamir.split_secret(master_passphrase, threshold, total_shares)

        print("\nMaster Key Shares (KEEP THESE SECURE AND SEPARATE):")
        print("-" * 200)

        for i, share in enumerate(shares, 1):
            x, y = share
            share_str = f"{x}:{y}"
            print(f"Share {i}: {share_str}")

        print("-" * 200)
        log_audit(admin_id, "Master Key Backup",
                  f"The administrator '{admin_full_name}' created {total_shares} backup shares of the master key with a threshold of {threshold}.",
                  session)

        print(f"Successfully created {total_shares} shares with a threshold of {threshold}.")
        print("IMPORTANT: Store each share in a separate, secure location.")
        print(f"You will need at least {threshold} shares to recover the master key.")

    except Exception as e:
        print(f"Error creating master key backup: {e}")
        import traceback
        traceback.print_exc()

    input("\nPress Enter to continue...")

def recover_master_key(admin_id, admin_full_name, session):
    print("-" * 200)
    print("Master Key Recovery")
    print("-" * 200)
    print("This process will reconstruct the master key from the provided shares.")
    print("WARNING: This is a critical operation that affects system security.")

    confirm = input("Do you want to proceed? (y/n): ")
    if confirm.lower() != 'y':
        print("Master key recovery cancelled.")
        return

    try:
        while True:
            try:
                share_count = int(input("How many shares will you provide? "))
                if share_count < 2:
                    print("You must provide at least 2 shares.")
                    continue
                break
            except ValueError:
                print("Please enter a valid number.")

        shares = []
        for i in range(1, share_count + 1):
            share_str = input(f"Enter Share {i} (format x:y): ").strip()
            try:
                x_str, y_str = share_str.split(':')
                x = int(x_str)
                y = int(y_str)
                shares.append((x, y))
            except:
                print(f"Error: Share {i} is not in valid format (should be x:y).")
                return

        try:
            shamir = ShamirSecretSharing()
            recovered_key = shamir.recover_secret(shares)
            print(recovered_key)

            try:
                if len(recovered_key) != 32:
                    print(f"Warning: Recovered key length ({len(recovered_key)}) doesn't match expected length (32).")

                test_aesgcm = AESGCM(recovered_key)
                test_data = b"test"
                test_nonce = os.urandom(12)
                test_encrypted = test_aesgcm.encrypt(test_nonce, test_data, None)
                test_decrypted = test_aesgcm.decrypt(test_nonce, test_encrypted, None)

                if test_data != test_decrypted:
                    print("Error: Key validation failed. The reconstructed key may be incorrect.")
                    return

            except Exception as e:
                print(f"Error validating the recovered key: {e}")
                print("The shares may be incorrect or corrupted.")
                return

            print("\nKey successfully reconstructed and validated!")
            update_confirm = input("Do you want to update the system's master key with this recovered key? (y/n): ")

            if update_confirm.lower() == 'y':
                try:
                    key_path = Path("hardware_security_module") / ("master_key") / ("master.key")
                    key_path.parent.mkdir(parents=True, exist_ok=True)

                    with open(key_path, 'wb') as key_file:
                        key_file.write(recovered_key)

                    os.chmod(key_path, 0o600)

                    log_audit(admin_id, "Master Key Recovery",
                              f"The administrator '{admin_full_name}' successfully recovered and applied the master key using {share_count} shares.",
                              session)

                    print(f"Master key has been successfully updated and stored at {key_path}")
                    print("The system is now using the recovered master key.")

                except Exception as e:
                    print(f"Error writing the master key to file: {e}")
            else:
                print("Master key update cancelled.")

        except Exception as e:
            print(f"Error recovering the master key: {e}")
            print("Make sure you have provided the correct shares and enough of them to meet the threshold.")
            import traceback
            traceback.print_exc()

    except Exception as e:
        print(f"Error during master key recovery: {e}")
        import traceback
        traceback.print_exc()

    input("\nHit Enter to continue.")

