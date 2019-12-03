from cryptography.hazmat.backends import default_backend
from hashlib import sha256
from message_type_pb2 import COMM_MESSAGE
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as paddings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import time
import zmq
import sys
import os
import socket
import json
from diffiehellman.diffiehellman import DiffieHellman

class Server():
    identities = None
    socket_from_client = None
    connection_from_client = None

    def login_proto(self):
        print ("something")
        Message = COMM_MESSAGE()
        
        data, temp = self.connection_from_client.recvfrom(4096)
        print (temp)
        Message.ParseFromString(data)
        
        
        if Message.type == Message.TYPE.LOGIN:
            N1 = os.urandom(16)
            N1 = N1.hex()
            print (N1)
        
            digest = sha256()
            digest.update(N1.encode())
            Message.N1_hash = digest.hexdigest()
            Message.message = N1[5:]
            self.connection_from_client.sendall (Message.SerializeToString())
        
            data, temp = self.connection_from_client.recvfrom(4096)
            print (temp)
            Message.ParseFromString(data)
        
            if Message.N1 == N1:
                print ("Puzzle figured out!")
            else:
                print ("Wrong!")
        
            bob = DiffieHellman(group=5, key_length=200)
            bob.generate_public_key()
            Message.gb_mod_p = str (bob.public_key)
            bob.generate_shared_secret(int (Message.message))
            Kas =  str(bob.shared_secret)[:16].encode()
            # Kas = (bob.shared_secret).to_bytes(16,sys.byteorder)
            print ("Shared secret is:", int.from_bytes (Kas, sys.byteorder))
            Message.gb_mod_p = str (bob.public_key)
        
            #### loading private key
            with open("private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend())
        
            #### encryption
            plain_text_sign = Message.message + "|" + Message.gb_mod_p
            plain_text_sign  = plain_text_sign.encode()
            ### sign the text
            signature = private_key.sign(
                plain_text_sign,
                paddings.PSS(
                    mgf=paddings.MGF1(hashes.SHA256()),
                    salt_length=paddings.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            #### Timestamp
            timestamp = str (int(time.time()))
            timestamp = timestamp.encode()
            plain_text = signature + timestamp
        
        
        
            iv = os.urandom(16)
            Message.iv = iv
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plain_text)
            padded_data += padder.finalize()
            plain_text_padded = padded_data
        
            authenticate_data = b'Final Project'
            # self.Message.authenticate_data = authenticate_data
        
            # GCM Mode, we also need an IV
            # encrypt
            cipher = Cipher(algorithms.AES(Kas), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(authenticate_data)
            cipher_text = encryptor.update(plain_text_padded) + encryptor.finalize()
            Message.cipher_text = cipher_text
            Message.tag = encryptor.tag
        
            self.connection_from_client.sendall(Message.SerializeToString())
        
            ### Decrypt and verify the client:
            data = self.connection_from_client.recv(4096)
            Message.ParseFromString(data)
            #  AES  decryption
            decryptor = Cipher(algorithms.AES(Kas), modes.GCM(iv, Message.tag),
                               backend=default_backend()).decryptor()
            decryptor.authenticate_additional_data(authenticate_data)
            decrypted_plain_text = decryptor.update(Message.cipher_text) + decryptor.finalize()
        
            # unpad
            unpadder = padding.PKCS7(128).unpadder()
            plain_text = unpadder.update(decrypted_plain_text) + unpadder.finalize()
        
            # Verify timestamp
            plain_text_timestamp = plain_text[-10:]
            message_timestamp = int (plain_text_timestamp)
            if ((int(time.time()) - message_timestamp) < 60):
                print ("Timestamp verified")
            else:
                print ("Timestamp failed!")
        
            ### 
            plain_text = plain_text[0:len(plain_text) - 10]
            plain_text = plain_text.decode()
            username  =  plain_text.split("|")[0]
            password = plain_text.split("|")[1]
            #if username == "Yushen" and password == "123":
            #    verify = "Success"
            #else:
            #   verify = "Fail"
            verify = "Fail"
            if username in self.identities.keys():
                pass_digest = sha256()
                pass_digest.update(password.encode())
                pass_digest.update(self.identities[username]["salt"].encode())
                pass_hash = pass_digest.hexdigest()
                print (pass_hash, "is the passhash")
                if pass_hash == self.identities[username]["passhash"]:
                    verify = "Success"
            ####
            plain_text =  verify.encode()
            timestamp = str(int(time.time()))
            timestamp = timestamp.encode()
            plain_text = plain_text + timestamp
        
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plain_text)
            padded_data += padder.finalize()
            plain_text_padded = padded_data
        
            cipher = Cipher(algorithms.AES(Kas), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(authenticate_data)
            cipher_text = encryptor.update(plain_text_padded) + encryptor.finalize()
            Message.cipher_text = cipher_text
            Message.tag = encryptor.tag
        
            self.connection_from_client.sendall(Message.SerializeToString())
            # connection_from_client.shutdown(0)
            # self.socket_from_client.shutdown(0)
            self.connection_from_client.close()
            self.socket_from_client.close()

    def __init__(self):
        self.identities = None
        with open("server_creds.json", "r") as creds:
            self.identities = json.loads(creds.read())
        self.socket_from_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_from_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serveraddress = ('localhost',9090)
        self.socket_from_client.bind(serveraddress)
        
        self.socket_from_client.listen(1)
        self.connection_from_client, client_address = self.socket_from_client.accept()
        # # print (connection_from_client[-1])
        # # print (connection_from_client[1])
        # print (connection_from_client)
        # print (connection_from_client.getpeername())

        # print (connection_from_client.getsockname())
        # print (client_address)
        self.login_proto()

if __name__ == '__main__':
    server = Server()
