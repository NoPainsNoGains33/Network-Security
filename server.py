import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from message_type_pb2 import COMM_MESSAGE

import json
from hashlib import sha256

def validate_pw(username, password):
    with open("users.json", 'r') as users:
        user_list = json.loads(users.read())
        for user in user_list:
            if user['name'] == user_name:
                passhash = sha256()
                passhash.update(password.encode())
                passhash.update(str(user['salt']).encode())
                assert user['hash'] == passhash.hexdigest()

class Server:
    def __init__(self):
        validate_pw("Ryan", 'ryan')

if __name__ == '__main__':
    server = Server()

## Will work on this after proper merge
# HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
# PORT = 9090        # Port to listen on (non-privileged ports are > 1023)
# 
# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#     s.bind((HOST, PORT))
#     s.listen()
#     conn, addr = s.accept()
#     N1 = 100
#     Message = COMM_MESSAGE ()
#     Message.N1 = 100
#     digest = hashes.Hash(hashes.SHA256, backend=default_backend())
#     digest.upgrate (N1)
#     Message.N1_hash = digest.finalize()
#     with conn:
#         print('Connected by', addr)
#         while True:
#             conn.send(Message.SerializeToString())
#             data = conn.recv(1024)
