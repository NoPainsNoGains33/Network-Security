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
