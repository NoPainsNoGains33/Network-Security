import socket
import zmq
import sys
import time
from hashlib import sha256
from message_type_pb2 import COMM_MESSAGE
from diffiehellman.diffiehellman import DiffieHellman
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as paddings
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

class Client():

    def __init__(self, c_name, c_password):
        self.client_name = c_name
        self.client_password = c_password
        self.authenticate_data =  b'Final Project'
        self.Message_send = COMM_MESSAGE()
        self.Message_rec = COMM_MESSAGE()

    def connect_to_server (self):
        context = zmq.Context()
        self.socket = context.socket(zmq.REQ)
        self.socket.bind("tcp://127.0.0.1:9090")
    
    def send_message (self):
        self.socket.send(self.Message_send.SerializeToString())

    def receive_message (self):
        data = self.socket.recv()
        self.Message_rec.ParseFromString(data)

    def verify_timestamp  (self, timestamp):
        time_now = int(time.time())
        plain_text_timestamp  = timestamp.decode()
        plain_text_timestamp  = int (plain_text_timestamp)
        if (time_now - plain_text_timestamp < 60):
            print ("Timestamp verified!")
            return True
        else:
            print ("Failed in Timestamp!")
            return False

    def encryption (self, plain_text):
        # AES encryption
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plain_text)
        padded_data += padder.finalize()
        plain_text_padded = padded_data
        ## GCM Mode
        cipher = Cipher(algorithms.AES(self.Kas), modes.GCM(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(self.authenticate_data)
        cipher_text = encryptor.update(plain_text_padded) + encryptor.finalize()
        self.Message_send.cipher_text = cipher_text
        self.Message_send.tag = encryptor.tag

    def decryption_with_timestamp (self):
        #  AES  decryption
        decryptor = Cipher(algorithms.AES(self.Kas), modes.GCM(self.iv, self.Message_rec.tag),
                           backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(self.authenticate_data)
        decrypted_plain_text = decryptor.update(self.Message_rec.cipher_text) + decryptor.finalize()

        # unpad
        unpadder = padding.PKCS7(128).unpadder()
        plain_text = unpadder.update(decrypted_plain_text) + unpadder.finalize()

        # Verify timestamp
        plain_text_timestamp = plain_text[-10:]
        plain_text = plain_text[0:len(plain_text) - 10]
        if (self.verify_timestamp(plain_text_timestamp)):
            ## return plain_text in bytes
            return plain_text
        else:
            sys.exit(1)

    def puzzle(self):
        self.Message_send.type = COMM_MESSAGE.TYPE.LOGIN

        #  send the first message to announce the server: "I want to log in"
        self.send_message()

        # receive from the server: puzzle
        self.receive_message()

        for i in range (0,int('100000',16)):
            i_hex = hex(i)[2:]
            answer = i_hex + self.Message_rec.message
            digest = sha256()
            digest.update(answer.encode())
            if digest.hexdigest() == self.Message_rec.N1_hash:
                break
        self.Message_send.N1  =  answer
        print ("Puzzle solved and the answer is:", i_hex)

    # set up the session key of client
    def session(self):
        alice = DiffieHellman (group=5, key_length=200)
        alice.generate_public_key()
        self.Message_send.message = str (alice.public_key)
        # send puzzle answer and ga mod p
        self.send_message()

        # receive the session key of server
        self.receive_message()

        alice.generate_shared_secret(int (self.Message_rec.gb_mod_p))
        # set up the session key Kas
        self.Kas = str(alice.shared_secret)[:16].encode()
        self.iv = self.Message_rec.iv
        print ("Shared secret is:", int.from_bytes (self.Kas, sys.byteorder))

        # Decryption
        plain_text = self.decryption_with_timestamp()

        # Verify signature
        correct_message = str(alice.public_key) + "|" + self.Message_rec.gb_mod_p
        correct_message = correct_message.encode()

        ## load public key
        with open("public_key.der", "rb") as key_file:
            public_key = serialization.load_der_public_key(
                key_file.read(),
                backend=default_backend())

        ##  verify the signature
        try:
            public_key.verify(
                plain_text,
                correct_message,
                paddings.PSS(
                    mgf=paddings.MGF1(hashes.SHA256()),
                    salt_length=paddings.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature verify success!")
        except:
            print('Error in verifying the signature!')
            sys.exit(1)

    def login (self):
        message = self.client_name  + "|" + self.client_password
        message = message.encode()
        timestamp = str (int (time.time())).encode()
        plain_text = message + timestamp
        # Encrypt the data
        self.encryption(plain_text)

        # Send the data
        self.send_message()

        # Receive the data
        self.receive_message()

        # Decrypt the data
        plain_text = self.decryption_with_timestamp()
        plain_text = plain_text.decode ()
        print (plain_text)

    def client_to_server_login (self):
        test_object.connect_to_server()
        test_object.puzzle()
        test_object.session()
        test_object.login()

    def get_name(self):
        return self.client_name, self.client_password


if __name__ == '__main__':
    print ("Please type your Username:")
    client_name = input()
    print ("Please type your Password:")
    client_password = input ()
    test_object = Client (client_name, client_password)
    print("The client name and password is", test_object.get_name())
    test_object.client_to_server_login()

