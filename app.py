import os
import stat
import argparse
import pwd
import sys

BANNER = r"""
 __  __ _           _                       _             
|  \/  (_)_ __ ___ (_) ___ ___  _ __  _   _| |_ ___  _ __ 
| |\/| | | '_ ` _ \| |/ __/ _ \| '_ \| | | | __/ _ \| '__|
| |  | | | | | | | | | (_| (_) | | | | |_| | || (_) | |   
|_|  |_|_|_| |_| |_|_|\___\___/|_| |_|\__,_|\__\___/|_|   
"""

def check_file_permissions(path, must_not_world_writable=True):
    """Check if file has dangerous permissions (world-writable)."""
    try:
        st = os.stat(path)
        mode = st.st_mode
        if must_not_world_writable and bool(mode & stat.S_IWOTH):
            return False, "World-writable"
        return True, "OK"
    except Exception as e:
        return None, f"Error: {e}"

def check_critical_files():
    """Check critical system files like /etc/passwd and /etc/shadow."""
    print("[*] Checking critical system files...")
    critical_files = ["/etc/passwd", "/etc/shadow"]
    for f in critical_files:
        status, message = check_file_permissions(f)
        if status is True:
            print(f"[+] {f} permissions OK ✅")
        elif status is False:
            print(f"[!] {f} has bad permissions ❌ ({message})")
        else:
            print(f"[?] Could not check {f} ({message})")

def check_env_vars():
    """Look for suspicious environment variables (like PATH ending with .)."""
    print("[*] Checking environment variables...")
    path_var = os.getenv("PATH", "")
    if path_var.endswith(":"):
        print("[!] PATH ends with ':' which may allow insecure binary execution ❌")
    else:
        print("[+] Environment variables look fine ✅")

def check_user_privileges():
    """Check if script runs as root."""
    print("[*] Checking user privileges...")
    if os.geteuid() == 0:
        print("[!] Running as root. Be cautious ❌")
    else:
        user = pwd.getpwuid(os.geteuid()).pw_name
        print(f"[+] Running as user: {user} ✅")

def run_all_checks():
    print(BANNER)
    check_user_privileges()
    print("-" * 50)
    check_critical_files()
    print("-" * 50)
    check_env_vars()
    print("-" * 50)
    print("[*] Misconfig checks completed.")

def parse_args():
    parser = argparse.ArgumentParser(description="Simple Misconfiguration Detector")
    parser.add_argument("--scan", action="store_true", help="Run all checks")
    return parser.parse_args()

def main():
    args = parse_args()
    if args.scan:
        run_all_checks()
    else:
        print("Usage: python3 misconfig_detector.py --scan")
        sys.exit(1)

if __name__ == "__main__":
    main()
