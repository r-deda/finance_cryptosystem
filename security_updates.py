import subprocess
import os
import sys
import datetime
import hashlib
import base64
import requests
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from models import Logs
from pathlib import Path

try:
    import importlib.metadata as importlib_metadata
except ImportError:
    try:
        import importlib_metadata
    except ImportError:
        import pkg_resources


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

def clear_screen():
    print("\n" * 100)

def get_installed_packages():
    try:
        try:
            installed_packages = []
            for dist in importlib_metadata.distributions():
                installed_packages.append({
                    'name': dist.metadata['Name'].lower(),
                    'version': dist.version
                })
            return installed_packages
        except (ImportError, AttributeError):
            installed_packages = []
            for pkg in pkg_resources.working_set:
                package_name = pkg.key if hasattr(pkg, 'key') else pkg.project_name
                installed_packages.append({
                    'name': package_name.lower(),
                    'version': pkg.version
                })
            return installed_packages
    except Exception as e:
        print(f"Error retrieving installed packages: {e}")
        return []

def get_package_vulnerabilities(package_name, package_version):
    try:
        api_url = f"https://pypi.org/pypi/{package_name}/json"
        response = requests.get(api_url, timeout=5)

        if response.status_code != 200:
            return {"error": "Could not retrieve package information"}

        data = response.json()
        latest_version = data.get('info', {}).get('version')

        if not latest_version:
            return {
                "current_version": package_version,
                "latest_version": package_version,
                "needs_update": False
            }

        from packaging import version

        if version.parse(latest_version) > version.parse(package_version):
            return {
                "current_version": package_version,
                "latest_version": latest_version,
                "needs_update": True
            }

        return {
            "current_version": package_version,
            "latest_version": latest_version,
            "needs_update": False
        }
    except Exception as e:
        return {"error": f"Error checking vulnerabilities: {str(e)}"}

def check_security_updates():
    print("-" * 200)
    print("Checking for Security Updates")
    print("-" * 200)

    installed_packages = get_installed_packages()

    if not installed_packages:
        print("Failed to retrieve installed packages.")
        return []

    critical_packages = ['cryptography', 'argon2-cffi', 'sqlalchemy', 'requests', 'pyotp']

    print(f"Checking {len(installed_packages)} installed packages for updates...")
    print(f"(Critical security packages are highlighted)")

    updates_available = []

    for pkg in installed_packages:
        is_critical = pkg['name'] in critical_packages

        if is_critical:
            print(f"Checking critical package: {pkg['name']} ({pkg['version']})...")
        else:
            print(f"Checking package: {pkg['name']} ({pkg['version']})...")

        vuln_info = get_package_vulnerabilities(pkg['name'], pkg['version'])

        if "error" in vuln_info:
            print(f"  Error checking {pkg['name']}: {vuln_info['error']}")
            continue

        if vuln_info.get("needs_update", False):
            updates_available.append({
                'name': pkg['name'],
                'current_version': vuln_info['current_version'],
                'latest_version': vuln_info['latest_version'],
                'is_critical': is_critical
            })

            if is_critical:
                status = "CRITICAL UPDATE REQUIRED"
            else:
                status = "Update available"

            print(f"  {status}: {pkg['name']} {vuln_info['current_version']} -> {vuln_info['latest_version']}")
        else:
            print(f"  Up to date: {pkg['name']} {pkg['version']}")

    return updates_available

def update_package(package_name):
    try:
        print(f"Updating {package_name}...")

        cmd = [sys.executable, "-m", "pip", "install", "--upgrade", package_name]

        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                startupinfo=startupinfo
            )
        else:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )

        if result.returncode != 0:
            print(f"Error updating {package_name}: {result.stderr}")
            return False

        print(f"Successfully updated {package_name}")
        return True
    except subprocess.SubprocessError as e:
        print(f"Error running pip for {package_name}: {str(e)}")
        return False
    except Exception as e:
        print(f"Unexpected error updating {package_name}: {str(e)}")
        return False

def apply_security_updates(admin_id, admin_full_name, session):
    clear_screen()
    print("-" * 200)
    print("Security Updates and Patch Management")
    print("-" * 200)

    missing_deps = []
    try:
        from packaging import version
    except ImportError:
        missing_deps.append("packaging")

    try:
        import importlib.metadata
    except ImportError:
        try:
            import importlib_metadata
        except ImportError:
            missing_deps.append("importlib-metadata")

    if missing_deps:
        print(f"Installing required dependencies: {', '.join(missing_deps)}...")
        try:
            for dep in missing_deps:
                cmd = [sys.executable, "-m", "pip", "install", dep]

                if os.name == 'nt':
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        check=False,
                        startupinfo=startupinfo
                    )
                else:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        check=False
                    )

                if result.returncode != 0:
                    raise Exception(f"Failed to install {dep}: {result.stderr}")

            print("Dependencies installed successfully.")
        except Exception as e:
            print(f"Error installing dependencies: {e}")
            print(f"Please install the following packages manually: {', '.join(missing_deps)}")
            log_audit(admin_id, "Security Update Error",
                      f"The administrator '{admin_full_name}' attempted to run security updates but required dependencies were missing.",
                      session)
            input("\nHit Enter to continue.")
            return

    print("Checking for available security updates...\n")
    updates = check_security_updates()

    if not updates:
        print("\nNo updates available. All packages are up to date.")
        log_audit(admin_id, "Security Check",
                  f"The administrator '{admin_full_name}' performed a security check. No updates were needed.", session)
        input("\nHit Enter to continue.")
        return

    critical_updates = [u for u in updates if u['is_critical']]
    other_updates = [u for u in updates if not u['is_critical']]

    if critical_updates:
        print("\nCRITICAL SECURITY UPDATES AVAILABLE:")
        for update in critical_updates:
            print(f"  - {update['name']}: {update['current_version']} -> {update['latest_version']}")

    if other_updates:
        print("\nOther updates available:")
        for update in other_updates:
            print(f"  - {update['name']}: {update['current_version']} -> {update['latest_version']}")

    if critical_updates:
        print("\nWARNING: Critical security updates are pending. It's recommended to apply these updates immediately.")

    confirmation = input("\nDo you want to apply the available updates? (y/n): ")

    if confirmation.lower() != 'y':
        log_audit(admin_id, "Security Updates Declined",
                  f"The administrator '{admin_full_name}' checked for security updates but declined to apply them.",
                  session)
        print("Update process cancelled.")
        input("\nHit Enter to continue.")
        return

    print("\nApplying security updates...")

    success_count = 0
    failed_count = 0
    update_details = []
    failed_updates = []

    all_updates = critical_updates + other_updates
    for update in all_updates:
        result = update_package(update['name'])
        update_status = "success" if result else "failed"

        update_details.append(
            f"{update['name']} ({update['current_version']} -> {update['latest_version']}): {update_status}")

        log_audit(
            admin_id,
            "Security Updates Applied",
            f"The administrator '{admin_full_name}' updated the '{update['name']}' libary from version {update['current_version']} to {update['latest_version']}.",
            session
        )

        if result:
            success_count += 1
        else:
            failed_count += 1
            failed_updates.append(update)

    update_summary = f"Applied {success_count} updates successfully"
    if failed_count > 0:
        update_summary += f", {failed_count} updates failed"


    print("\n" + "-" * 200)
    print(f"Update process completed. {update_summary}.")
    if failed_count > 0:
        print("Failed updates:")
        for update in failed_updates:
            print(f"  - {update['name']} ({update['current_version']} -> {update['latest_version']})")

    input("\nHit Enter to continue.")