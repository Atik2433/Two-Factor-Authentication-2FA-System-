
import tkinter as tk
from tkinter import ttk, messagebox
import json, os, hashlib, secrets, time, threading, re, sys

USERS_FILE = "users.json"
OTP_LENGTH = 6
OTP_TTL = 120         # seconds
RESEND_COOLDOWN = 30  # seconds
MAX_OTP_ATTEMPTS = 3

# ---------------------------
# Utilities
# ---------------------------
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        try:
            return json.load(f)
        except:
            return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

def generate_salt():
    return secrets.token_hex(8)

def generate_otp(n=OTP_LENGTH):
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(n))

# ---------------------------
# TwoFAManager
# ---------------------------
class TwoFAManager:
    def __init__(self):
        # store emails lowercased to enforce case-insensitive uniqueness
        self.users = load_users()
        # ensure keys are lowercase in-memory (migration safe)
        self.users = {k.lower(): v for k, v in self.users.items()}
        self.otp_store = {}

    def register_user(self, username, password):
        key = username.lower()
        if key in self.users:
            return False, "This Gmail is already registered."
        salt = generate_salt()
        self.users[key] = {"salt": salt, "password_hash": hash_password(password, salt)}
        save_users(self.users)
        return True, "Registered successfully."

    def verify_credentials(self, username, password):
        user = self.users.get(username.lower())
        if not user:
            return False
        return user["password_hash"] == hash_password(password, user["salt"])

    def send_otp(self, username):
        now = time.time()
        record = self.otp_store.get(username.lower(), {})
        last_sent = record.get("last_sent_ts", 0)
        if now - last_sent < RESEND_COOLDOWN:
            wait = int(RESEND_COOLDOWN - (now - last_sent))
            return False, f"Wait {wait}s before resending."
        otp = generate_otp()
        self.otp_store[username.lower()] = {
            "otp": otp,
            "expiry": now + OTP_TTL,
            "attempts_left": MAX_OTP_ATTEMPTS,
            "last_sent_ts": now
        }
        return True, otp

    def verify_otp(self, username, otp_input):
        record = self.otp_store.get(username.lower())
        if not record:
            return False, "No OTP requested yet."
        now = time.time()
        if now > record["expiry"]:
            return False, "OTP expired."
        if record["attempts_left"] <= 0:
            return False, "Maximum attempts used."
        if otp_input == record["otp"]:
            self.otp_store.pop(username.lower(), None)
            return True, "OTP verified."
        else:
            record["attempts_left"] -= 1
            if record["attempts_left"] <= 0:
                self.otp_store.pop(username.lower(), None)
                return False, "Wrong OTP. Attempts over."
            return False, f"Wrong OTP. Attempts left: {record['attempts_left']}"

    def get_registered_emails(self):
        # return a sorted list for display
        return sorted(self.users.keys())

# ---------------------------
# GUI App
# ---------------------------
class App(tk.Tk):
    def __init__(self, manager: TwoFAManager):
        super().__init__()
        self.title("Secure 2FA Login (Gmail Only)")
        self.geometry("640x520")
        self.resizable(False, False)
        self.manager = manager

        # center the window
        self.update_idletasks()
        w, h = 640, 520
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

        self.style = ttk.Style(self)
        try:
            self.style.theme_use('clam')
        except:
            pass

        # styles
        self.style.configure("Root.TFrame", background="#eff3f8")
        self.style.configure("Card.TFrame", background="white", relief="raised")
        self.style.configure("TLabel", background="#eff3f8", font=("Segoe UI", 11))
        self.style.configure("Title.TLabel", background="#eff3f8", font=("Segoe UI", 20, "bold"), foreground="#1f3a57")
        self.style.configure("Subtitle.TLabel", background="#eff3f8", font=("Segoe UI", 10), foreground="#4a5568")
        self.style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=8)
        self.style.map("Accent.TButton", background=[("active", "#1d6fa5")])

        self.create_widgets()

    def create_widgets(self):
        root = ttk.Frame(self, style="Root.TFrame", padding=18)
        root.pack(fill="both", expand=True)

        ttk.Label(root, text="Secure 2FA Login", style="Title.TLabel").pack(pady=(2,2))
        ttk.Label(root, text="Gmail-only • OTP verification (simulated)", style="Subtitle.TLabel").pack(pady=(0,12))

        # top actions: view registered
        top_actions = ttk.Frame(root, padding=(0,6), style="Root.TFrame")
        top_actions.pack(fill="x", pady=(0,6))
        ttk.Button(top_actions, text="View Registered Gmail(s)", style="Accent.TButton", command=self.open_registered_popup).pack(side="right")

        card = ttk.Frame(root, style="Card.TFrame", padding=18)
        card.pack(fill="both", expand=True)

        notebook = ttk.Notebook(card)
        notebook.pack(fill="both", expand=True)

        # Login tab
        self.login_frame = ttk.Frame(notebook, padding=18)
        self.register_frame = ttk.Frame(notebook, padding=18)
        notebook.add(self.login_frame, text="Login")
        notebook.add(self.register_frame, text="Register")

        # --- Login ---
        ttk.Label(self.login_frame, text="Gmail:").grid(row=0, column=0, sticky="w", pady=8)
        self.login_user = ttk.Entry(self.login_frame, width=36)
        self.login_user.grid(row=0, column=1, pady=8, sticky="w")

        ttk.Label(self.login_frame, text="Password:").grid(row=1, column=0, sticky="w", pady=8)
        self.login_pass = ttk.Entry(self.login_frame, width=36, show="*")
        self.login_pass.grid(row=1, column=1, pady=8, sticky="w")

        self.btn_login = ttk.Button(self.login_frame, text="Login & Send OTP", command=self.start_login_flow)
        self.btn_login.grid(row=2, column=0, columnspan=2, pady=(12,6), sticky="ew")

        ttk.Separator(self.login_frame).grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)

        ttk.Label(self.login_frame, text="OTP (6 digits):").grid(row=4, column=0, sticky="w", pady=8)
        self.otp_entry = ttk.Entry(self.login_frame, width=22)
        self.otp_entry.grid(row=4, column=1, pady=8, sticky="w")

        self.btn_verify_otp = ttk.Button(self.login_frame, text="Verify OTP", command=self.verify_otp_flow, state="disabled")
        self.btn_verify_otp.grid(row=5, column=0, pady=8, sticky="ew")

        self.btn_resend = ttk.Button(self.login_frame, text="Resend OTP", command=self.resend_otp_flow, state="disabled")
        self.btn_resend.grid(row=5, column=1, pady=8, sticky="ew")

        self.login_status = ttk.Label(self.login_frame, text="", foreground="red")
        self.login_status.grid(row=6, column=0, columnspan=2, pady=6)

        for child in self.login_frame.winfo_children():
            child.grid_configure(padx=6)

        # --- Register ---
        ttk.Label(self.register_frame, text="Gmail address:").grid(row=0, column=0, sticky="w", pady=8)
        self.reg_user = ttk.Entry(self.register_frame, width=36)
        self.reg_user.grid(row=0, column=1, pady=8, sticky="w")

        ttk.Label(self.register_frame, text="Password:").grid(row=1, column=0, sticky="w", pady=8)
        self.reg_pass = ttk.Entry(self.register_frame, width=36, show="*")
        self.reg_pass.grid(row=1, column=1, pady=8, sticky="w")

        ttk.Label(self.register_frame, text="Confirm password:").grid(row=2, column=0, sticky="w", pady=8)
        self.reg_pass2 = ttk.Entry(self.register_frame, width=36, show="*")
        self.reg_pass2.grid(row=2, column=1, pady=8, sticky="w")

        self.btn_register = ttk.Button(self.register_frame, text="Register Gmail", command=self.register_flow)
        self.btn_register.grid(row=3, column=0, columnspan=2, pady=(12,6), sticky="ew")

        self.reg_status = ttk.Label(self.register_frame, text="", foreground="green")
        self.reg_status.grid(row=4, column=0, columnspan=2, pady=6)

        for child in self.register_frame.winfo_children():
            child.grid_configure(padx=6)

    # -------------------
    # Registration
    # -------------------
    def register_flow(self):
        u = self.reg_user.get().strip()
        p = self.reg_pass.get().strip()
        p2 = self.reg_pass2.get().strip()
        if not u or not p:
            self.reg_status.config(text="Enter Gmail and password.")
            return
        if not re.match(r"^[a-zA-Z0-9._%+-]+@gmail\.com$", u):
            self.reg_status.config(text="Only Gmail addresses allowed.")
            return
        if p != p2:
            self.reg_status.config(text="Passwords do not match.")
            return
        ok, msg = self.manager.register_user(u, p)
        self.reg_status.config(text=msg)
        if ok:
            self.reg_user.delete(0, tk.END)
            self.reg_pass.delete(0, tk.END)
            self.reg_pass2.delete(0, tk.END)

    # -------------------
    # Login / OTP flows
    # -------------------
    def start_login_flow(self):
        username = self.login_user.get().strip()
        password = self.login_pass.get().strip()
        if not username or not password:
            self.login_status.config(text="Enter Gmail and password.")
            return
        if not re.match(r"^[a-zA-Z0-9._%+-]+@gmail\.com$", username):
            self.login_status.config(text="Login only allowed with Gmail addresses.")
            return
        if not self.manager.verify_credentials(username, password):
            self.login_status.config(text="Invalid Gmail or password.")
            return
        ok, payload = self.manager.send_otp(username)
        if not ok:
            self.login_status.config(text=payload)
            return

        otp_value = payload
        # show simulated OTP with selectable field + copy button
        self.show_otp_popup(username, otp_value)

        # enable OTP controls
        self.btn_verify_otp.config(state="normal")
        self.btn_resend.config(state="normal")
        self.login_status.config(text="OTP sent (simulated).")

        # start resend cooldown UI
        threading.Thread(target=self._resend_countdown, args=(username,), daemon=True).start()

    def resend_otp_flow(self):
        username = self.login_user.get().strip()
        if not username:
            self.login_status.config(text="Enter Gmail first.")
            return
        ok, payload = self.manager.send_otp(username)
        if not ok:
            self.login_status.config(text=payload)
            return
        otp_value = payload
        self.show_otp_popup(username, otp_value)
        self.login_status.config(text="Resent OTP (simulated).")
        threading.Thread(target=self._resend_countdown, args=(username,), daemon=True).start()

    def verify_otp_flow(self):
        username = self.login_user.get().strip()
        otp_in = self.otp_entry.get().strip()
        if not otp_in:
            self.login_status.config(text="Enter the OTP.")
            return
        ok, msg = self.manager.verify_otp(username, otp_in)
        if ok:
            messagebox.showinfo("Success", f"Welcome, {username}! 2FA succeeded.")
            self.otp_entry.delete(0, tk.END)
            self.btn_verify_otp.config(state="disabled")
            self.btn_resend.config(state="disabled")
            self.login_status.config(text="Logged in.")
        else:
            self.login_status.config(text=msg)

    # -------------------
    # OTP popup (selectable + copy)
    # -------------------
    def show_otp_popup(self, username, otp):
        popup = tk.Toplevel(self)
        popup.title("Simulated Gmail — OTP Sent")
        popup.geometry("480x200")
        popup.resizable(False, False)
        # delivery label
        ttk.Label(popup, text=f"To: {username}", font=("Segoe UI", 11, "bold")).pack(pady=(10,6))
        # instructions
        ttk.Label(popup, text=f"Your One-Time Password (expires in {OTP_TTL//60} min):", font=("Segoe UI", 10)).pack()

        # readonly entry showing OTP (so user can select/copy)
        entry_frame = ttk.Frame(popup, padding=8)
        entry_frame.pack(pady=(6,6))
        otp_var = tk.StringVar(value=otp)
        otp_display = ttk.Entry(entry_frame, textvariable=otp_var, font=("Courier", 14), justify="center", width=12)
        otp_display.pack(side="left", padx=(6,8))
        # make it read-only but selectable: disable usually prevents selection on some systems,
        # so use state="readonly" via tk.Entry widget instead if needed
        try:
            otp_display.state(["readonly"])
        except:
            otp_display.config(state="readonly")

        # Copy button
        def copy_otp():
            self.clipboard_clear()
            self.clipboard_append(otp)
            popup.clipboard_clear()
            popup.clipboard_append(otp)
            messagebox.showinfo("Copied", "OTP copied to clipboard.")

        ttk.Button(entry_frame, text="Copy OTP", command=copy_otp).pack(side="left", padx=(6,6))
        ttk.Button(popup, text="OK", command=popup.destroy).pack(pady=(10,12))

        # Also print OTP to terminal for quick testing/copying
        print(f"[SIMULATED OTP] {username} -> {otp}", file=sys.stdout)

    # -------------------
    # Registered emails popup (select + copy)
    # -------------------
    def open_registered_popup(self):
        emails = self.manager.get_registered_emails()
        popup = tk.Toplevel(self)
        popup.title("Registered Gmail(s)")
        popup.geometry("520x360")
        popup.resizable(False, False)

        ttk.Label(popup, text="Registered Gmail addresses:", font=("Segoe UI", 11, "bold")).pack(pady=(10,8))

        list_frame = ttk.Frame(popup, padding=8)
        list_frame.pack(fill="both", expand=True)

        # A scrollbar + listbox for selection
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical")
        listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, selectmode="browse", font=("Segoe UI", 11))
        scrollbar.config(command=listbox.yview)
        scrollbar.pack(side="right", fill="y")
        listbox.pack(side="left", fill="both", expand=True, padx=(0,4))

        for e in emails:
            listbox.insert(tk.END, e)

        btn_frame = ttk.Frame(popup, padding=8)
        btn_frame.pack(fill="x", pady=(6,10))

        def copy_selected():
            sel = listbox.curselection()
            if not sel:
                messagebox.showinfo("Select one", "Please select an email to copy.")
                return
            val = listbox.get(sel[0])
            self.clipboard_clear()
            self.clipboard_append(val)
            popup.clipboard_clear()
            popup.clipboard_append(val)
            messagebox.showinfo("Copied", f"Copied: {val}")

        def copy_all():
            all_text = "\n".join(listbox.get(0, tk.END))
            if not all_text:
                messagebox.showinfo("No entries", "No registered Gmail addresses found.")
                return
            self.clipboard_clear()
            self.clipboard_append(all_text)
            popup.clipboard_clear()
            popup.clipboard_append(all_text)
            messagebox.showinfo("Copied", "All registered Gmail addresses copied to clipboard.")

        ttk.Button(btn_frame, text="Copy Selected", command=copy_selected).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Copy All", command=copy_all).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Close", command=popup.destroy).pack(side="right", padx=6)

    # -------------------
    # Resend cooldown visual
    # -------------------
    def _resend_countdown(self, username):
        # Disable and show countdown on the Resend button
        self.btn_resend.config(state="disabled")
        start = time.time()
        while True:
            remaining = int(RESEND_COOLDOWN - (time.time() - start))
            if remaining <= 0:
                break
            try:
                self.btn_resend.config(text=f"Resend OTP ({remaining}s)")
            except tk.TclError:
                pass
            time.sleep(1)
        try:
            self.btn_resend.config(text="Resend OTP", state="normal")
        except tk.TclError:
            pass

# ---------------------------
# main
# ---------------------------
def main():
    manager = TwoFAManager()
    app = App(manager)
    app.mainloop()

if __name__ == "__main__":
    main()
