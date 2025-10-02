import sys
import socket
import threading
import json
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, # type: ignore
                               QTextEdit, QLineEdit, QPushButton, QLabel, QListWidget, QTabWidget,
                               QInputDialog, QMessageBox, QStatusBar, QDialog, QListWidgetItem,
                               QStackedWidget) # type: ignore
from PySide6.QtCore import QThread, Signal, QObject, Slot, Qt # type: ignore

from cryptography.hazmat.primitives import serialization # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa, padding # type: ignore
from cryptography.hazmat.primitives import hashes # type: ignore

# State constants
SERVER_HOST = '0.tcp.in.ngrok.io'
SERVER_PORT = 17461

# Encryption
key_pair = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_pem = key_pair.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Worker thread for socket communication
class SocketWorker(QObject):
    received_message = Signal(dict)
    connection_status = Signal(str)

    def __init__(self, client_socket):
        super().__init__()
        self.client_socket = client_socket

    def run(self):
        try:
            self.connection_status.emit("Connected to server.")
            while True:
                data = self.client_socket.recv(16384)
                if not data:
                    break
                msg = json.loads(data.decode())
                self.received_message.emit(msg)
        except Exception as e:
            self.connection_status.emit(f"Connection lost: {e}")
        finally:
            self.client_socket.close()

class ChatClient(QMainWindow):
    def __init__(self):
        super().__init__()
        self.username = None
        self.public_keys = {}
        self.groups = {}
        self.is_connected = False
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.worker_thread = None
        self.socket_worker = None

        self.setup_login_ui()

    def setup_login_ui(self):
        self.setWindowTitle("PySide6 Encrypted Chat")
        self.setGeometry(100, 100, 400, 200)
        self.setStyleSheet("background-color: #282a36; color: #f8f8f2;")

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        label = QLabel("Enter your username to connect")
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.username_input.setStyleSheet("background-color: #313244; border: none; padding: 8px; border-radius: 5px;")
        self.username_input.returnPressed.connect(self.attempt_login)
        layout.addWidget(self.username_input)

        self.connect_button = QPushButton("Connect")
        self.connect_button.setStyleSheet("""
            QPushButton { background-color: #50fa7b; color: #282a36; border: none; padding: 10px; border-radius: 5px; font-weight: bold; }
            QPushButton:hover { background-color: #8aff8a; }
            QPushButton:pressed { background-color: #3aae4d; }
        """)
        self.connect_button.clicked.connect(self.attempt_login)
        layout.addWidget(self.connect_button)
        
        self.statusBar = QStatusBar()
        self.statusBar.setStyleSheet("background-color: #343746; color: #f8f8f2;")
        self.setStatusBar(self.statusBar)

    def setup_main_ui(self):
        self.setWindowTitle(f"PySide6 Encrypted Chat - {self.username}")
        self.setGeometry(100, 100, 800, 600)
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)

        left_panel = QWidget()
        left_panel.setFixedWidth(200)
        left_panel.setStyleSheet("background-color: #343746; border-right: 1px solid #44475a;")
        left_layout = QVBoxLayout(left_panel)
        
        self.user_list_widget = QListWidget()
        self.user_list_widget.setStyleSheet("""
            QListWidget { background-color: #1a1c24; border: 1px solid #44475a; border-radius: 5px; color: #f8f8f2; }
            QListWidget::item { padding: 5px; }
            QListWidget::item:selected { background-color: #50fa7b; color: #282a36; }
        """)
        self.user_list_widget.itemClicked.connect(self.handle_user_clicked)
        left_layout.addWidget(self.user_list_widget)

        create_group_btn = QPushButton("Create Group")
        create_group_btn.setStyleSheet("background-color: #50fa7b; color: #282a36; border: none; padding: 8px; border-radius: 5px; font-weight: bold;")
        create_group_btn.clicked.connect(self.create_group)
        left_layout.addWidget(create_group_btn)
        
        main_layout.addWidget(left_panel)
        
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        # Use QStackedWidget to manage different views
        self.stacked_widget = QStackedWidget()
        right_layout.addWidget(self.stacked_widget)

        # Welcome page
        welcome_page = QWidget()
        welcome_layout = QVBoxLayout(welcome_page)
        welcome_label = QLabel("Welcome! Select a user or create a group to start a chat.")
        welcome_label.setAlignment(Qt.AlignCenter)
        welcome_label.setStyleSheet("font-size: 16px; font-style: italic; color: #6272a4;")
        welcome_layout.addWidget(welcome_label)
        
        self.stacked_widget.addWidget(welcome_page)

        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane { border: 0; }
            QTabBar::tab { background: #44475a; color: #f8f8f2; padding: 8px 15px; border-top-left-radius: 5px; border-top-right-radius: 5px; margin-right: 2px; }
            QTabBar::tab:selected { background: #282a36; border-bottom: 2px solid #50fa7b; }
            QTabBar::tab:hover { background: #50fa7b; color: #282a36; }
        """)
        self.stacked_widget.addWidget(self.tab_widget)

        main_layout.addWidget(right_panel)

    def attempt_login(self):
        if self.is_connected:
            self.statusBar.showMessage("Already connected to the server.")
            return

        username = self.username_input.text().strip()
        if not username:
            self.statusBar.showMessage("Username cannot be empty.")
            return

        self.username = username
        self.statusBar.showMessage("Connecting to server...")

        try:
            self.client_socket.connect((SERVER_HOST, SERVER_PORT))
            self.is_connected = True

            login_payload = json.dumps({
                "username": self.username,
                "public_key": public_key_pem
            }).encode()
            self.client_socket.send(login_payload)
            
            self.setup_main_ui()

            self.worker_thread = QThread()
            self.socket_worker = SocketWorker(self.client_socket)
            self.socket_worker.moveToThread(self.worker_thread)
            
            self.worker_thread.started.connect(self.socket_worker.run)
            self.socket_worker.received_message.connect(self.handle_received_message)
            self.socket_worker.connection_status.connect(self.statusBar.showMessage)
            
            self.worker_thread.start()

        except Exception as e:
            self.statusBar.showMessage(f"Connection Error: {e}")
            self.is_connected = False

    def create_chat_tab(self, chat_id, title):
        tab_widget = QWidget()
        layout = QVBoxLayout(tab_widget)
        
        message_display = QTextEdit()
        message_display.setReadOnly(True)
        message_display.setStyleSheet("background-color: #1a1c24; border: none; font-family: Consolas; color: #f8f8f2; padding: 10px; border-radius: 5px;")
        layout.addWidget(message_display)
        
        input_layout = QHBoxLayout()
        message_input = QLineEdit()
        message_input.setPlaceholderText("Type a message...")
        message_input.setStyleSheet("background-color: #313244; border: none; padding: 8px; border-radius: 5px; color: #f8f8f2;")
        
        send_button = QPushButton("Send")
        send_button.setStyleSheet("background-color: #50fa7b; color: #282a36; border: none; padding: 8px 15px; border-radius: 5px; font-weight: bold;")
        
        input_layout.addWidget(message_input)
        input_layout.addWidget(send_button)
        layout.addLayout(input_layout)
        
        send_button.clicked.connect(lambda: self.send_message(message_input, message_display, chat_id, title))
        message_input.returnPressed.connect(lambda: self.send_message(message_input, message_display, chat_id, title))
        
        return tab_widget

    def create_group(self):
        online_users = [self.user_list_widget.item(i).text() for i in range(self.user_list_widget.count())]
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Create New Group")
        dialog.setStyleSheet("background-color: #282a36; color: #f8f8f2;")
        dialog_layout = QVBoxLayout(dialog)

        name_input = QLineEdit()
        name_input.setPlaceholderText("Enter Group Name")
        name_input.setStyleSheet("background-color: #313244; border: none; padding: 8px; border-radius: 5px; color: #f8f8f2;")
        dialog_layout.addWidget(name_input)

        user_list = QListWidget()
        user_list.setStyleSheet("background-color: #1a1c24; border: none; color: #f8f8f2; border-radius: 5px;")
        dialog_layout.addWidget(user_list)
        
        for user in online_users:
            item = QListWidgetItem(user)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            user_list.addItem(item)

        create_btn = QPushButton("Create")
        create_btn.setStyleSheet("background-color: #50fa7b; color: #282a36; border: none; padding: 8px; border-radius: 5px; font-weight: bold;")
        create_btn.clicked.connect(dialog.accept)
        dialog_layout.addWidget(create_btn)

        if dialog.exec() == QDialog.Accepted:
            group_name = name_input.text().strip()
            if not group_name:
                QMessageBox.warning(self, "Warning", "Group name cannot be empty.")
                return
            
            selected_members = [user_list.item(i).text() for i in range(user_list.count()) if user_list.item(i).checkState() == Qt.Checked]
            if not selected_members:
                QMessageBox.warning(self, "Warning", "Please select at least one member.")
                return

            selected_members.append(self.username)
            payload = json.dumps({"type": "create_group", "name": group_name, "members": selected_members}).encode()
            self.client_socket.send(payload)
            self.statusBar.showMessage(f"Request to create group '{group_name}' sent.")

    def handle_user_clicked(self, item):
        target_user = item.text()
        self.open_private_chat(target_user)

    def open_private_chat(self, target_user):
        self.stacked_widget.setCurrentIndex(1) # Switch to the chat tabs view

        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i) == target_user:
                self.tab_widget.setCurrentIndex(i)
                return

        new_tab = self.create_chat_tab(target_user, target_user)
        self.tab_widget.addTab(new_tab, target_user)
        self.tab_widget.setCurrentWidget(new_tab)
        
        self.statusBar.showMessage(f"Switched to private chat with {target_user}")

        request = json.dumps({"type": "private_request", "target": target_user}).encode()
        self.client_socket.send(request)

    def get_or_create_chat_widget(self, chat_id, title):
        self.stacked_widget.setCurrentIndex(1) # Switch to the chat tabs view
        
        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i) == title:
                return self.tab_widget.widget(i).findChild(QTextEdit)
        
        new_tab = self.create_chat_tab(chat_id, title)
        self.tab_widget.addTab(new_tab, title)
        return new_tab.findChild(QTextEdit)
    
    @Slot(dict)
    def handle_received_message(self, msg):
        mtype = msg.get("type")
        
        if mtype == "user_list":
            self.user_list_widget.clear()
            for user in msg["users"]:
                if user != self.username:
                    self.user_list_widget.addItem(user)
                    if user not in self.public_keys:
                        request = json.dumps({"type": "private_request", "target": user}).encode()
                        self.client_socket.send(request)
        
        elif mtype == "public_key":
            self.public_keys[msg["from"]] = msg["public_key"]

        elif mtype == "private_message":
            sender = msg["from"]
            message_hex = msg.get("message")
            decrypted = self.decrypt_message(bytes.fromhex(message_hex))

            messages_widget = self.get_or_create_chat_widget(sender, sender)
            if messages_widget:
                if decrypted:
                    messages_widget.append(f"[{sender}]: {decrypted}")
                else:
                    messages_widget.append(f"[{sender}]: <DECRYPTION FAILED>")
        
        elif mtype == "group_invite":
            group_id = msg.get("group_id")
            group_name = msg.get("name")
            response = QMessageBox.question(self, "Group Invitation", f"You have been invited to join group '{group_name}'. Do you accept?", QMessageBox.Yes | QMessageBox.No)
            
            if response == QMessageBox.Yes:
                payload = json.dumps({"type": "join_group", "group_id": group_id}).encode()
                self.client_socket.send(payload)
        
        elif mtype == "group_update":
            group_id = msg.get("group_id")
            group_name = msg.get("name")
            members = msg.get("members")
            
            self.groups[group_id] = {"name": group_name, "members": members}
            self.get_or_create_chat_widget(group_id, group_name)
            self.statusBar.showMessage(f"You have joined group '{group_name}'.")

        elif mtype == "group_message":
            group_id = msg.get("group_id")
            sender = msg.get("from")
            message_hex = msg.get("message")
            decrypted = self.decrypt_message(bytes.fromhex(message_hex))
            
            if group_id in self.groups:
                group_name = self.groups[group_id]["name"]
                messages_widget = self.get_or_create_chat_widget(group_id, group_name)
                
                if messages_widget:
                    if decrypted:
                        messages_widget.append(f"[{sender}]: {decrypted}")
                    else:
                        messages_widget.append(f"[{sender}]: <DECRYPTION FAILED>")
            else:
                 self.statusBar.showMessage(f"Message received for unknown group ID: {group_id}")

    def send_message(self, input_field, messages_widget, chat_id, title):
        msg = input_field.text().strip()
        if not msg:
            return

        input_field.clear()

        if chat_id == "General":
            encrypted_messages = {}
            for user in self.public_keys:
                encrypted = self.encrypt_for_user(user, msg)
                if encrypted:
                    encrypted_messages[user] = encrypted.hex()
            
            if encrypted_messages:
                payload = json.dumps({"type": "group_message", "group_id": chat_id, "messages": encrypted_messages}).encode()
                self.client_socket.send(payload)
            
            messages_widget.append(f"[You]: {msg}")

        elif chat_id in self.public_keys:
            target_user = chat_id
            encrypted = self.encrypt_for_user(target_user, msg)
            if encrypted:
                payload = json.dumps({"type": "private_message", "message": encrypted.hex(), "target": target_user}).encode()
                self.client_socket.send(payload)
                messages_widget.append(f"[You]: {msg}")
            else:
                messages_widget.append(f"System: No public key for {target_user}")
        
        else: # Group chat with a specific ID
            encrypted_messages = {}
            members = self.groups[chat_id]["members"]
            for member in members:
                encrypted = self.encrypt_for_user(member, msg)
                if encrypted:
                    encrypted_messages[member] = encrypted.hex()
            
            if encrypted_messages:
                payload = json.dumps({"type": "group_message", "group_id": chat_id, "messages": encrypted_messages}).encode()
                self.client_socket.send(payload)
            
            messages_widget.append(f"[You]: {msg}")

    def encrypt_for_user(self, username, plaintext):
        pubkey_pem = self.public_keys.get(username)
        if not pubkey_pem:
            return None
        pubkey = serialization.load_pem_public_key(pubkey_pem.encode())
        ciphertext = pubkey.encrypt(
            plaintext.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return ciphertext

    def decrypt_message(self, ciphertext):
        try:
            plaintext = key_pair.decrypt(
                ciphertext,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            return plaintext.decode()
        except Exception:
            return None

if __name__ == "__main__":
    app = QApplication(sys.argv)
    chat_app = ChatClient()
    chat_app.show()
    sys.exit(app.exec())
