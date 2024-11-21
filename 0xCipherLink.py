import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import socket
import threading
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import struct

# Key Derivation and Padding Utilities
def derive_key(password):
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def pad_data(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

# File Sending and Receiving Functions
def send_file(sock, filename, password, progress_callback):
    key = derive_key(password)
    with open(filename, 'rb') as file:
        file_data = file.read()
        file_data = pad_data(file_data)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        filename_bytes = os.path.basename(filename).encode()
        sock.sendall(struct.pack('I', len(filename_bytes)) + filename_bytes)
        sock.sendall(iv + encrypted_data)
        progress_callback(100)  # Transfer complete

def receive_file(key, port, progress_callback):
    host = '0.0.0.0'
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_socket.bind((host, port))
    receiver_socket.listen(1)

    client_socket, _ = receiver_socket.accept()

    filename_len = struct.unpack('I', client_socket.recv(4))[0]
    filename = client_socket.recv(filename_len).decode()

    encrypted_data = b""
    while True:
        chunk = client_socket.recv(4096)
        if not chunk:
            break
        encrypted_data += chunk
        progress_callback(len(encrypted_data) / len(encrypted_data))  # Simulated progress

    decrypted_data = decrypt_data(key, encrypted_data)
    with open(filename, 'wb') as file:
        file.write(decrypted_data)

    client_socket.close()
    receiver_socket.close()

def decrypt_data(key, data):
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return unpad_data(decrypted_data)

# GUI Functions
def choose_file():
    filename = filedialog.askopenfilename()
    file_path_label.config(text=filename)

def send_file_gui():
    host = host_entry.get()
    port = port_entry.get()
    password = password_entry.get()
    filename = file_path_label.cget("text")
    if not (host and port and password and filename):
        messagebox.showerror("Error", "Please fill all fields and select a file.")
        return
    try:
        port = int(port)
        sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sender_socket.connect((host, port))
        threading.Thread(target=send_file, args=(sender_socket, filename, password, update_progress)).start()
    except Exception as e:
        messagebox.showerror("Error", str(e))

def receive_file_gui():
    port = port_entry.get()
    password = password_entry.get()
    if not (port and password):
        messagebox.showerror("Error", "Please enter port and password.")
        return
    try:
        port = int(port)
        threading.Thread(target=receive_file, args=(derive_key(password), port, update_progress)).start()
    except Exception as e:
        messagebox.showerror("Error", str(e))

def update_progress(value):
    progress_bar['value'] = value
    progress_label.config(text=f"{value}%")

# GUI Setup
root = tk.Tk()
root.title("0xCipherLink")
root.geometry('400x500')
root.resizable(False, False)

# Styling
root.configure(bg='#1e1e2f')

def configure_widget(widget, font=('Helvetica', 10, 'bold'), bg='#1e1e2f', fg='white'):
    widget.configure(bg=bg, fg=fg, font=font)
    if isinstance(widget, tk.Entry):
        widget.configure(insertbackground='white')

# Header
header = tk.Label(root, text="0xCipherLink by Ricky", font=('Helvetica', 16, 'bold'))
configure_widget(header, font=('Helvetica', 16, 'bold'), fg='#ffcc00')
header.pack(pady=10)

# Mode Selection
mode_var = tk.StringVar(value="send")
mode_frame = tk.Frame(root, bg='#1e1e2f')
send_radio = tk.Radiobutton(mode_frame, text="Send", variable=mode_var, value="send", selectcolor='black')
configure_widget(send_radio)
send_radio.pack(side=tk.LEFT, padx=10)
receive_radio = tk.Radiobutton(mode_frame, text="Receive", variable=mode_var, value="receive", selectcolor='black')
configure_widget(receive_radio)
receive_radio.pack(side=tk.LEFT, padx=10)
mode_frame.pack(pady=10)

# Host and Port Inputs
host_label = tk.Label(root, text="Enter Host:")
configure_widget(host_label)
host_label.pack(pady=5)
host_entry = tk.Entry(root)
configure_widget(host_entry)
host_entry.pack(pady=5)

port_label = tk.Label(root, text="Enter Port:")
configure_widget(port_label)
port_label.pack(pady=5)
port_entry = tk.Entry(root)
configure_widget(port_entry)
port_entry.pack(pady=5)

# Password Input
password_label = tk.Label(root, text="Enter Password:")
configure_widget(password_label)
password_label.pack(pady=5)
password_entry = tk.Entry(root, show="*")
configure_widget(password_entry)
password_entry.pack(pady=5)

# File Selection
file_path_label = tk.Label(root, text="No file chosen")
configure_widget(file_path_label)
file_path_label.pack(pady=5)
choose_file_button = tk.Button(root, text="Choose File", command=choose_file)
configure_widget(choose_file_button)
choose_file_button.pack(pady=5)

# Execute Button
execute_button = tk.Button(root, text="Execute", command=lambda: send_file_gui() if mode_var.get() == "send" else receive_file_gui())
configure_widget(execute_button, font=('Helvetica', 12, 'bold'), bg='#ff6600')
execute_button.pack(pady=10)

# Progress Bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
progress_bar.pack(pady=10)
progress_label = tk.Label(root, text="0%", font=('Helvetica', 10))
configure_widget(progress_label)
progress_label.pack()

root.mainloop()
