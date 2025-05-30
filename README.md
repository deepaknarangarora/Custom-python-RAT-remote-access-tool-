# Custom Python RAT (Remote Access Tool)

A fully functional Remote Access Tool (RAT) built in Python with a GUI interface, encrypted communication, and advanced features such as file upload/download, keylogger, webcam snapshot, and persistence. This project is developed for educational purposes in cybersecurity.

---

## Features

- Encrypted client-server communication using Fernet symmetric encryption  
- Graphical User Interface (GUI) for server controller using Tkinter  
- Remote shell command execution  
- File upload and download functionality  
- Keylogger to capture keystrokes on the client machine  
- Webcam snapshot capture and viewing  
- Persistence on Windows to start client automatically on system boot  
- Robust reconnect and debug logging  

---

## Requirements

- Python 3.x  
- Required Python libraries:
  - cryptography  
  - tkinter (usually included with Python)  
  - pynput  
  - opencv-python (optional, for webcam snapshot)  
  - Pillow  

Install dependencies using pip:

```bash
pip install cryptography pynput opencv-python Pillow
