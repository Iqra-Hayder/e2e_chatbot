import socket
import threading
import json
import uuid

# Server constants
HOST = '0.0.0.0'
PORT = 8888

# Data structures
clients = {}  # username -> conn
public_keys = {}  # username -> public_key
groups = {"General": {"id": "General", "name": "General", "members": []}} # group_id -> {"name": str, "members": []}

# Thread-safe lock
lock = threading.Lock()

def broadcast_user_list():
    """Send the updated list of connected users to everyone"""
    with lock:
        user_list = list(clients.keys())
    payload = json.dumps({'type': 'user_list', 'users': user_list}).encode()
    for conn in clients.values():
        try:
            conn.send(payload)
        except:
            pass  

def handle_client(conn, addr):
    username = None
    try:
        raw = conn.recv(4096).decode()
        login = json.loads(raw)
        username = login['username']
        pubkey = login['public_key']

        with lock:
            clients[username] = conn
            public_keys[username] = pubkey
            groups["General"]["members"].append(username)

        print(f"[+] {username} connected from {addr}")
        broadcast_user_list()

        while True:
            raw = conn.recv(16384).decode()
            if not raw:
                break

            msg = json.loads(raw)
            mtype = msg.get("type")

            if mtype == "private_request":
                target_user = msg["target"]
                if target_user in public_keys:
                    response = json.dumps({
                        "type": "public_key",
                        "from": target_user,
                        "public_key": public_keys[target_user]
                    }).encode()
                    conn.send(response)

            elif mtype == "private_message":
                target = msg["target"]
                if target in clients:
                    payload = json.dumps({
                        "type": "private_message",
                        "from": username,
                        "message": msg["message"]
                    }).encode()
                    clients[target].send(payload)

            elif mtype == "create_group":
                group_name = msg["name"]
                members = msg["members"]
                new_group_id = str(uuid.uuid4())
                with lock:
                    groups[new_group_id] = {"id": new_group_id, "name": group_name, "members": []}
                    for member in members:
                        if member == username:
                            groups[new_group_id]["members"].append(username)
                            
                        else:
                            if member in clients:
                                payload = json.dumps({
                                    "type": "group_invite",
                                    "group_id": new_group_id,
                                    "name": group_name
                                }).encode()
                                clients[member].send(payload)

            elif mtype == "join_group":
                group_id = msg["group_id"]
                if group_id in groups:
                    with lock:
                        if username not in groups[group_id]["members"]:
                            groups[group_id]["members"].append(username)
                    
                    # Notify all members of the update
                    group_update_payload = json.dumps({
                        "type": "group_update",
                        "group_id": group_id,
                        "name": groups[group_id]["name"],
                        "members": groups[group_id]["members"]
                    }).encode()
                    for member in groups[group_id]["members"]:
                        if member in clients:
                            clients[member].send(group_update_payload)
            
            elif mtype == "group_message":
                group_id = msg["group_id"]
                group_payload = msg["messages"]
                
                if group_id in groups:
                    members = groups[group_id]["members"]
                    with lock:
                        for target_user, enc_msg in group_payload.items():
                            if target_user in clients and target_user in members:
                                payload = json.dumps({
                                    "type": "group_message",
                                    "group_id": group_id,
                                    "from": username,
                                    "message": enc_msg
                                }).encode()
                                try:
                                    clients[target_user].send(payload)
                                except:
                                    pass

    except Exception as e:
        print(f"[!] Error with {username or addr}: {e}")

    finally:
        with lock:
            if username:
                clients.pop(username, None)
                public_keys.pop(username, None)
                for group in groups.values():
                    if username in group["members"]:
                        group["members"].remove(username)
        conn.close()
        broadcast_user_list()
        print(f"[-] {username or addr} disconnected.")

def start_server():
    print(f"[*] Starting server on {HOST}:{PORT}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
