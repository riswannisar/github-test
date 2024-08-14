import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import sqlite3
import bcrypt
import os
import shutil
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Initialize the database
conn = sqlite3.connect('app.db')
c = conn.cursor()

# Create users table
c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )''')

# Create files table
c.execute('''CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                filename TEXT,
                filepath TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )''')
conn.commit()

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")
        self.create_login_page()

    def create_login_page(self):
        self.clear_root()

        self.frame = ttk.Frame(self.root, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.lbl_username = ttk.Label(self.frame, text="Username:")
        self.lbl_username.grid(row=0, column=0, padx=5, pady=5)
        self.entry_username = ttk.Entry(self.frame)
        self.entry_username.grid(row=0, column=1, padx=5, pady=5)

        self.lbl_password = ttk.Label(self.frame, text="Password:")
        self.lbl_password.grid(row=1, column=0, padx=5, pady=5)
        self.entry_password = ttk.Entry(self.frame, show='*')
        self.entry_password.grid(row=1, column=1, padx=5, pady=5)

        self.btn_login = ttk.Button(self.frame, text="Login", command=self.login)
        self.btn_login.grid(row=2, column=1, padx=5, pady=5)

        self.btn_signup = ttk.Button(self.frame, text="Sign Up", command=self.create_signup_page)
        self.btn_signup.grid(row=3, column=1, padx=5, pady=5)

    def create_signup_page(self):
        self.clear_root()

        self.frame = ttk.Frame(self.root, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.lbl_name = ttk.Label(self.frame, text="Name:")
        self.lbl_name.grid(row=0, column=0, padx=5, pady=5)
        self.entry_name = ttk.Entry(self.frame)
        self.entry_name.grid(row=0, column=1, padx=5, pady=5)

        self.lbl_email = ttk.Label(self.frame, text="Email:")
        self.lbl_email.grid(row=1, column=0, padx=5, pady=5)
        self.entry_email = ttk.Entry(self.frame)
        self.entry_email.grid(row=1, column=1, padx=5, pady=5)

        self.lbl_username = ttk.Label(self.frame, text="Username:")
        self.lbl_username.grid(row=2, column=0, padx=5, pady=5)
        self.entry_username = ttk.Entry(self.frame)
        self.entry_username.grid(row=2, column=1, padx=5, pady=5)

        self.lbl_password = ttk.Label(self.frame, text="Password:")
        self.lbl_password.grid(row=3, column=0, padx=5, pady=5)
        self.entry_password = ttk.Entry(self.frame, show='*')
        self.entry_password.grid(row=3, column=1, padx=5, pady=5)

        self.btn_register = ttk.Button(self.frame, text="Register", command=self.signup)
        self.btn_register.grid(row=4, column=1, padx=5, pady=5)

    def create_home_page(self):
        self.clear_root()

        self.frame = ttk.Frame(self.root, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.lbl_welcome = ttk.Label(self.frame, text=f"Welcome, {self.current_user}")
        self.lbl_welcome.grid(row=0, column=0, padx=5, pady=5)

        self.btn_upload = ttk.Button(self.frame, text="Upload File", command=self.upload_file)
        self.btn_upload.grid(row=1, column=0, padx=5, pady=5)

        self.lbl_files = ttk.Label(self.frame, text="Uploaded Files:")
        self.lbl_files.grid(row=2, column=0, padx=5, pady=5)

        self.listbox_files = tk.Listbox(self.frame, height=10)
        self.listbox_files.grid(row=3, column=0, padx=5, pady=5)
        
        self.load_files()

        self.btn_download = ttk.Button(self.frame, text="Download Selected File", command=self.download_file)
        self.btn_download.grid(row=4, column=0, padx=5, pady=5)

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        c.execute("SELECT id, password FROM users WHERE username=?", (username,))
        user = c.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[1]):
            self.current_user = username
            self.user_id = user[0]
            self.create_home_page()
        else:
            messagebox.showerror("Login Error", "Invalid username or password")

    def signup(self):
        name = self.entry_name.get()
        email = self.entry_email.get()
        username = self.entry_username.get()
        password = self.entry_password.get()

        c.execute("SELECT id FROM users WHERE username=?", (username,))
        if c.fetchone():
            messagebox.showerror("Signup Error", "Username already exists")
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            c.execute("INSERT INTO users (name, email, username, password) VALUES (?, ?, ?, ?)", 
                      (name, email, username, hashed_password))
            conn.commit()
            messagebox.showinfo("Signup Success", "Registration successful")
            self.create_login_page()

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            file_name = os.path.basename(file_path)
            user_dir = os.path.join("uploads", str(self.user_id))
            os.makedirs(user_dir, exist_ok=True)
            dest_path = os.path.join(user_dir, file_name)
            shutil.copy(file_path, dest_path)
            c.execute("INSERT INTO files (user_id, filename, filepath) VALUES (?, ?, ?)", 
                      (self.user_id, file_name, dest_path))
            conn.commit()
            messagebox.showinfo("File Upload", f"File '{file_name}' uploaded successfully")
            self.load_files()

    def load_files(self):
        self.listbox_files.delete(0, tk.END)
        c.execute("SELECT filename FROM files WHERE user_id=?", (self.user_id,))
        user_files = c.fetchall()
        for file in user_files:
            self.listbox_files.insert(tk.END, file[0])

    def send_otp(self, email):
        self.otp = random.randint(100000, 999999)

        # Replace these with your email details
        sender_email = "fku404040@gmail.com"
        sender_password = "irmplwwratpwjmxa"
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = email
        message["Subject"] = "Your OTP Code"

        body = f"Your OTP code is {self.otp}. Please enter this code to proceed with your file download."
        message.attach(MIMEText(body, "plain"))

        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            text = message.as_string()
            server.sendmail(sender_email, email, text)
            server.quit()
            messagebox.showinfo("OTP Sent", f"OTP has been sent to {email}")
        except Exception as e:
            messagebox.showerror("Email Error", f"Failed to send OTP: {e}")

    def verify_otp(self):
        entered_otp = simpledialog.askinteger("OTP Verification", "Enter the OTP sent to your email:")
        return entered_otp == self.otp

    def download_file(self):
        selected_file = self.listbox_files.get(tk.ACTIVE)
        if selected_file:
            c.execute("SELECT filepath FROM files WHERE user_id=? AND filename=?", (self.user_id, selected_file))
            file_path = c.fetchone()[0]
            
            c.execute("SELECT email FROM users WHERE id=?", (self.user_id,))
            email = c.fetchone()[0]

            self.send_otp(email)

            if self.verify_otp():
                download_dir = filedialog.askdirectory()
                if download_dir:
                    shutil.copy(file_path, os.path.join(download_dir, selected_file))
                    messagebox.showinfo("File Download", f"File '{selected_file}' downloaded to '{download_dir}'")
            else:
                messagebox.showerror("OTP Error", "Invalid OTP entered. Download aborted.")

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
