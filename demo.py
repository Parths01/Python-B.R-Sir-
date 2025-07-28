import tkinter as tk
from tkinter import ttk, messagebox
import json, os, hashlib
from datetime import datetime

class UserAuth:
    def __init__(self, users_file="users.json"):
        self.users_file = users_file
        self.users = self.load_users()

    def load_users(self):
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=4)

    def hash_password(self, pwd):
        return hashlib.sha256(pwd.encode()).hexdigest()

    def register_user(self, username, email, password):
        if username in self.users:
            return False, "Username already exists!"
        if any(u.get('email') == email for u in self.users.values()):
            return False, "Email already registered!"
        self.users[username] = {
            'email': email,
            'password': self.hash_password(password),
            'created_at': datetime.now().isoformat()
        }
        self.save_users()
        return True, "Registration successful!"

    def login_user(self, username, password):
        user = self.users.get(username)
        if not user:
            return False, "Username not found!"
        if user['password'] != self.hash_password(password):
            return False, "Invalid password!"
        return True, "Login successful!"

class ModernLoginApp:
    def __init__(self):
        self.root = tk.Tk()
        self.auth = UserAuth()
        self.root.title("Modern Login System")
        self.root.geometry("450x600")
        self.root.configure(bg='#2c3e50')
        self.root.resizable(False, False)
        self.center_window()
        self.setup_styles()
        self.create_frames()
        self.show_login()

    def center_window(self):
        self.root.update_idletasks()
        w, h = self.root.winfo_width(), self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f'{w}x{h}+{x}+{y}')

    def setup_styles(self):
        s = ttk.Style()
        s.theme_use('clam')
        s.configure('Title.TLabel', font=('Helvetica', 24, 'bold'), foreground='#ecf0f1', background='#2c3e50')
        s.configure('Subtitle.TLabel', font=('Helvetica', 10), foreground='#bdc3c7', background='#2c3e50')
        s.configure('Modern.TEntry', font=('Helvetica', 12), fieldbackground='#34495e', foreground='#ecf0f1', borderwidth=1, insertcolor='#ecf0f1')
        s.configure('Modern.TButton', font=('Helvetica', 12, 'bold'), foreground='#ecf0f1', background='#3498db', borderwidth=0, focuscolor='none')
        s.map('Modern.TButton', background=[('active', '#2980b9'), ('pressed', '#21618c')])
        s.configure('Link.TButton', font=('Helvetica', 10, 'underline'), foreground='#3498db', background='#2c3e50', borderwidth=0, focuscolor='none')
        s.map('Link.TButton', foreground=[('active', '#2980b9')], background=[('active', '#2c3e50')])

    def create_frames(self):
        # Login Frame
        self.login_frame = tk.Frame(self.root, bg='#2c3e50')
        ttk.Label(self.login_frame, text="Welcome Back", style='Title.TLabel').pack(pady=(50, 10))
        ttk.Label(self.login_frame, text="Please sign in to your account", style='Subtitle.TLabel').pack(pady=(0, 40))
        ttk.Label(self.login_frame, text="Username", style='Subtitle.TLabel').pack(anchor='w', padx=50)
        self.login_username = ttk.Entry(self.login_frame, width=30, style='Modern.TEntry')
        self.login_username.pack(pady=(5, 20), padx=50, fill='x')
        ttk.Label(self.login_frame, text="Password", style='Subtitle.TLabel').pack(anchor='w', padx=50)
        self.login_password = ttk.Entry(self.login_frame, width=30, show="*", style='Modern.TEntry')
        self.login_password.pack(pady=(5, 30), padx=50, fill='x')
        ttk.Button(self.login_frame, text="SIGN IN", style='Modern.TButton', command=self.handle_login).pack(pady=(0, 20), padx=50, fill='x')
        sf = tk.Frame(self.login_frame, bg='#2c3e50')
        sf.pack(pady=20)
        ttk.Label(sf, text="Don't have an account?", style='Subtitle.TLabel').pack(side='left')
        ttk.Button(sf, text="Sign Up", style='Link.TButton', command=self.show_signup).pack(side='left', padx=(5, 0))
        self.login_username.bind('<Return>', lambda e: self.handle_login())
        self.login_password.bind('<Return>', lambda e: self.handle_login())

        # Signup Frame
        self.signup_frame = tk.Frame(self.root, bg='#2c3e50')
        ttk.Label(self.signup_frame, text="Create Account", style='Title.TLabel').pack(pady=(50, 10))
        ttk.Label(self.signup_frame, text="Join us today", style='Subtitle.TLabel').pack(pady=(0, 30))
        ttk.Label(self.signup_frame, text="Username", style='Subtitle.TLabel').pack(anchor='w', padx=50)
        self.signup_username = ttk.Entry(self.signup_frame, width=30, style='Modern.TEntry')
        self.signup_username.pack(pady=(5, 15), padx=50, fill='x')
        ttk.Label(self.signup_frame, text="Email", style='Subtitle.TLabel').pack(anchor='w', padx=50)
        self.signup_email = ttk.Entry(self.signup_frame, width=30, style='Modern.TEntry')
        self.signup_email.pack(pady=(5, 15), padx=50, fill='x')
        ttk.Label(self.signup_frame, text="Password", style='Subtitle.TLabel').pack(anchor='w', padx=50)
        self.signup_password = ttk.Entry(self.signup_frame, width=30, show="*", style='Modern.TEntry')
        self.signup_password.pack(pady=(5, 15), padx=50, fill='x')
        ttk.Label(self.signup_frame, text="Confirm Password", style='Subtitle.TLabel').pack(anchor='w', padx=50)
        self.signup_confirm_password = ttk.Entry(self.signup_frame, width=30, show="*", style='Modern.TEntry')
        self.signup_confirm_password.pack(pady=(5, 25), padx=50, fill='x')
        ttk.Button(self.signup_frame, text="CREATE ACCOUNT", style='Modern.TButton', command=self.handle_signup).pack(pady=(0, 20), padx=50, fill='x')
        sf2 = tk.Frame(self.signup_frame, bg='#2c3e50')
        sf2.pack(pady=15)
        ttk.Label(sf2, text="Already have an account?", style='Subtitle.TLabel').pack(side='left')
        ttk.Button(sf2, text="Sign In", style='Link.TButton', command=self.show_login).pack(side='left', padx=(5, 0))
        for widget in [self.signup_username, self.signup_email, self.signup_password, self.signup_confirm_password]:
            widget.bind('<Return>', lambda e: self.handle_signup())

    def show_login(self):
        self.signup_frame.pack_forget()
        self.login_frame.pack(fill='both', expand=True)
        self.login_username.focus()

    def show_signup(self):
        self.login_frame.pack_forget()
        self.signup_frame.pack(fill='both', expand=True)
        self.signup_username.focus()

    def handle_login(self):
        u, p = self.login_username.get().strip(), self.login_password.get().strip()
        if not u or not p:
            messagebox.showerror("Error", "Please fill in all fields!"); return
        success, msg = self.auth.login_user(u, p)
        if success:
            messagebox.showinfo("Success", f"Welcome back, {u}!")
            self.show_dashboard(u)
        else:
            messagebox.showerror("Error", msg)

    def handle_signup(self):
        u, e = self.signup_username.get().strip(), self.signup_email.get().strip()
        p, cp = self.signup_password.get().strip(), self.signup_confirm_password.get().strip()
        if not all([u, e, p, cp]):
            messagebox.showerror("Error", "Please fill in all fields!"); return
        if len(u) < 3:
            messagebox.showerror("Error", "Username must be at least 3 characters!"); return
        if len(p) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters!"); return
        if p != cp:
            messagebox.showerror("Error", "Passwords do not match!"); return
        if '@' not in e or '.' not in e:
            messagebox.showerror("Error", "Please enter a valid email!"); return
        success, msg = self.auth.register_user(u, e, p)
        if success:
            messagebox.showinfo("Success", "Account created! You can now sign in.")
            self.clear_signup_fields()
            self.show_login()
        else:
            messagebox.showerror("Error", msg)

    def clear_signup_fields(self):
        for w in [self.signup_username, self.signup_email, self.signup_password, self.signup_confirm_password]:
            w.delete(0, tk.END)

    def show_dashboard(self, username):
        self.login_frame.pack_forget()
        self.signup_frame.pack_forget()
        dashboard = tk.Frame(self.root, bg='#2c3e50')
        dashboard.pack(fill='both', expand=True)
        ttk.Label(dashboard, text=f"Welcome, {username}!", style='Title.TLabel').pack(pady=(100, 20))
        user = self.auth.users[username]
        info = f"Email: {user['email']}\nMember since: {user['created_at'][:10]}"
        ttk.Label(dashboard, text=info, style='Subtitle.TLabel').pack(pady=20)
        ttk.Button(dashboard, text="LOGOUT", style='Modern.TButton', command=self.logout).pack(pady=50)
        self.dashboard_frame = dashboard

    def logout(self):
        self.login_username.delete(0, tk.END)
        self.login_password.delete(0, tk.END)
        for w in self.root.winfo_children():
            w.destroy()
        self.create_frames()
        self.show_login()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    ModernLoginApp().run()
