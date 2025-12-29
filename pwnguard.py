import hashlib
import requests
import argparse
import concurrent.futures
import secrets
import string
from colorama import Fore, Style, init
from prettytable import PrettyTable

# Initialize colorama for colored terminal output
init(autoreset=True)

class PwnGuardPro:
    def __init__(self):
        # API URL for Pwned Passwords using k-Anonymity
        self.api_url = "https://api.pwnedpasswords.com/range/"

    def generate_secure_password(self, length=16):
        """Generates a cryptographically strong password using secure random symbols."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for i in range(length))

    def check_api(self, password):
        try:
            # Convert password to SHA-1 hash
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            # Request only the first 5 characters of the hash (Privacy-focused)
            response = requests.get(self.api_url + prefix, timeout=10)
            
            if response.status_code != 200:
                return password, "Error", 0, None

            # Check if the remaining hash suffix exists in the results
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    # If breached, generate a smart suggestion immediately
                    suggestion = self.generate_secure_password()
                    return password, True, int(count), suggestion
            
            return password, False, 0, None
        except Exception:
            return password, "Error", 0, None

def main():
    # Setup CLI Arguments
    parser = argparse.ArgumentParser(description="PwnGuard Pro: Breach Scanner & Secure Suggestion Engine")
    parser.add_argument("-f", "--file", required=True, help="Path to the password list file")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Number of concurrent threads")
    args = parser.parse_args()

    scanner = PwnGuardPro()
    
    try:
        # Read unique passwords from file
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = list(set([line.strip() for line in f if line.strip()]))
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading file: {e}")
        return

    print(f"\n{Fore.CYAN}[*] PwnGuard Pro: Scanning & Securing Process Started...")
    print(f"{Fore.CYAN}[*] Loaded {len(passwords)} unique passwords. Using {args.threads} threads.\n")
    
    # Initialize Report Table
    table = PrettyTable()
    table.field_names = ["Original Password", "Leaked Count", "Status", "Suggested Secure Password"]
    table.align["Original Password"] = "l"
    table.align["Suggested Secure Password"] = "l"

    # Start multi-threaded scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_pwd = {executor.submit(scanner.check_api, p): p for p in passwords}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_pwd)):
            pwd, status, count, suggestion = future.result()
            
            if status is True:
                table.add_row([pwd, f"{count:,}", Fore.RED + "BREACHED", Fore.GREEN + suggestion])
            elif status is False:
                table.add_row([pwd, "0", Fore.GREEN + "SAFE", "N/A (Already Secure)"])
            else:
                table.add_row([pwd, "N/A", Fore.YELLOW + "ERROR", "N/A"])
            
            # Live progress tracker
            print(f"{Fore.WHITE}Progress: {i+1}/{len(passwords)}", end='\r')

    # Display final report
    print("\n" + str(table))
    print(f"\n{Fore.CYAN}[+] Scan Complete. Stay Secure!")

if __name__ == "__main__":
    main()