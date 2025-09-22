# Updated Version for Phase 1 + Modern GUI + Single Excel Integration

import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import face_recognition
import cv2
import numpy as np
import os
import sqlite3
import pandas as pd
import pytesseract
import smtplib
import random
from datetime import datetime

# Paths
KNOWN_FACES_DIR = "known_faces"
DATABASE_FILE = "car_security.db"
EXCEL_FILE = "security_logs.xlsx"
OTP_EMAIL = "youremail@example.com"  # replace with your email
OTP_PASSWORD = "yourpassword"  # replace with your email password

# Database Setup
conn = sqlite3.connect(DATABASE_FILE)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (name TEXT, plate TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS logs (name TEXT, plate TEXT, timestamp TEXT, status TEXT)''')
conn.commit()

# Initialize Excel File
if not os.path.exists(EXCEL_FILE):
    df = pd.DataFrame(columns=['Name', 'Plate', 'Timestamp', 'Status'])
    df.to_excel(EXCEL_FILE, index=False)

# Load known faces
known_faces = []
known_names = []
if os.path.exists(KNOWN_FACES_DIR):
    for name in os.listdir(KNOWN_FACES_DIR):
        img_path = os.path.join(KNOWN_FACES_DIR, name)
        img = face_recognition.load_image_file(img_path)
        encodings = face_recognition.face_encodings(img)
        if encodings:
            known_faces.append(encodings[0])
            known_names.append(os.path.splitext(name)[0])

# OTP Sending

def send_otp():
    otp = str(random.randint(1000, 9999))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(OTP_EMAIL, OTP_PASSWORD)
        server.sendmail(OTP_EMAIL, OTP_EMAIL, f"Subject: Car Security OTP\n\nYour OTP is: {otp}")
        server.quit()
    except Exception as e:
        print("Error sending OTP:", e)
    return otp

# Log data to SQLite and Excel

def log_event(name, plate, status):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (name, plate, timestamp, status) VALUES (?, ?, ?, ?)", (name, plate, timestamp, status))
    conn.commit()
    conn.close()

    if os.path.exists(EXCEL_FILE):
        df = pd.read_excel(EXCEL_FILE)
        new_row = pd.DataFrame({"Name": [name], "Plate": [plate], "Timestamp": [timestamp], "Status": [status]})
        df = pd.concat([df, new_row], ignore_index=True)
        df.to_excel(EXCEL_FILE, index=False)

# GUI Application

class CarSecurityApp:
    def __init__(self, master):
        self.master = master
        master.title("\U0001F697 Car Security System")
        master.geometry("600x500")
        master.configure(bg="#e3f2fd")

        self.style = ttk.Style()
        self.style.configure('TButton', font=('Helvetica', 14), padding=12)
        self.style.configure('TLabel', background="#e3f2fd", font=('Helvetica', 14))

        self.title = tk.Label(master, text="\U0001F512 Car Security System", font=("Helvetica", 26, "bold"), bg="#e3f2fd", fg="#0d47a1")
        self.title.pack(pady=20)

        self.authenticate_button = ttk.Button(master, text="Authenticate User", command=self.authenticate)
        self.authenticate_button.pack(pady=20)

        self.admin_login_button = ttk.Button(master, text="Admin Panel", command=self.open_admin_panel)
        self.admin_login_button.pack(pady=10)

        self.exit_button = ttk.Button(master, text="Exit", command=master.quit)
        self.exit_button.pack(pady=20)

    def authenticate(self):
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        cap.release()

        if not ret:
            messagebox.showerror("Error", "Failed to access webcam.")
            return

        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame)
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

        if face_encodings:
            match = face_recognition.compare_faces(known_faces, face_encodings[0])

            if True in match:
                matched_idx = match.index(True)
                name = known_names[matched_idx]
                messagebox.showinfo("Success", f"Face Verified: {name}")
                plate = self.scan_plate()
                self.verify_license(name, plate)
            else:
                messagebox.showwarning("Warning", "Face not recognized. OTP Verification required.")
                self.otp_authentication()
        else:
            messagebox.showwarning("Warning", "No face detected!")

    def scan_plate(self):
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        cap.release()

        if not ret:
            messagebox.showerror("Error", "Failed to capture plate.")
            return "Unknown"

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        text = pytesseract.image_to_string(gray)
        plate = ''.join(e for e in text if e.isalnum())[:10]
        return plate

    def verify_license(self, name, plate):
        conn = sqlite3.connect(DATABASE_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE name=? AND plate=?", (name, plate))
        result = c.fetchone()
        conn.close()

        if result:
            messagebox.showinfo("Success", "License Verified! Access Granted.")
            log_event(name, plate, "Access Granted")
        else:
            messagebox.showerror("Failed", "License Verification Failed. Access Denied.")
            log_event(name, plate, "Access Denied")

    def otp_authentication(self):
        otp_generated = send_otp()

        otp_window = tk.Toplevel(self.master)
        otp_window.title("OTP Verification")
        otp_window.geometry("350x250")
        otp_window.configure(bg="#e3f2fd")

        tk.Label(otp_window, text="Enter OTP sent to your Email", font=("Helvetica", 14)).pack(pady=20)
        otp_entry = tk.Entry(otp_window, font=("Helvetica", 16))
        otp_entry.pack(pady=10)

        def verify_otp():
            if otp_entry.get() == otp_generated:
                messagebox.showinfo("Success", "OTP Verified!")
                plate = self.scan_plate()
                self.verify_license("OTP_User", plate)
                otp_window.destroy()
            else:
                messagebox.showerror("Error", "Incorrect OTP!")
                log_event("Unknown", "Unknown", "OTP Verification Failed")
                otp_window.destroy()

        ttk.Button(otp_window, text="Verify", command=verify_otp).pack(pady=20)

    def open_admin_panel(self):
        admin_window = tk.Toplevel(self.master)
        admin_window.title("Admin Panel")
        admin_window.geometry("600x400")
        admin_window.configure(bg="#e3f2fd")

        ttk.Label(admin_window, text="Registered Users", font=("Helvetica", 18, "bold")).pack(pady=10)
        tree = ttk.Treeview(admin_window, columns=("Name", "Plate"), show='headings')
        tree.heading("Name", text="Name")
        tree.heading("Plate", text="Plate")
        tree.pack(fill="both", expand=True, padx=20, pady=10)

        conn = sqlite3.connect(DATABASE_FILE)
        c = conn.cursor()
        c.execute("SELECT name, plate FROM users")
        users = c.fetchall()
        conn.close()

        for user in users:
            tree.insert('', 'end', values=user)

if __name__ == "__main__":
    root = tk.Tk()
    app = CarSecurityApp(root)
    root.mainloop()
