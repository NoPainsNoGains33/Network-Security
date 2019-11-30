import socket
import zmq
import sys
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

    def connect_to_server (self):
        context = zmq.Context()
        socket = context.socket(zmq.REQ)
        socket.bind("tcp://127.0.0.1:9090")
        return socket


    def puzzle(self, socket):
        Message_send = COMM_MESSAGE ()
        Message_send.type = COMM_MESSAGE.TYPE.LOGIN
        Message_rec = COMM_MESSAGE ()
        socket.send(Message_send.SerializeToString())
        data = socket.recv()
        Message_rec.ParseFromString(data)
        for i in range (0,1000):
            digest = sha256()
            digest.update(str(i).encode())
            if Message_rec.N1_hash == digest.hexdigest():
                return  i

    def session(self, socket, puzzle):
        # set up the session key of client
        Message_send = COMM_MESSAGE ()
        Message_send.type = COMM_MESSAGE.TYPE.LOGIN
        Message_rec =  COMM_MESSAGE ()
        Message_send.N1  = puzzle
        alice = DiffieHellman (group=5, key_length=200)
        alice.generate_public_key()
        # Message_send.ga_mod_p = str (alice.public_key)
        Message_send.message = str (alice.public_key)
        socket.send(Message_send.SerializeToString())
        # print ("My DH is:", Message_send.message)

        # receive the session key of server
        data = socket.recv()
        Message_rec.ParseFromString(data)
        # print ("Server DH is:", Message_rec.message)

        alice.generate_shared_secret(int (Message_rec.gb_mod_p))
        Kas = str(alice.shared_secret)[:16].encode()
        # print ('Kas type is:', type (Kas))
        # print ('Length of Kas is:', len (Kas))
        print ("Shared secret is:", int.from_bytes (Kas, sys.byteorder))

        decryptor = Cipher(algorithms.AES(Kas), modes.GCM(Message_rec.iv, Message_rec.tag), backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(Message_rec.authenticate_data)
        decrypted_plain_text = decryptor.update(Message_rec.cipher_text) + decryptor.finalize()

        #unpad
        unpadder = padding.PKCS7(128).unpadder()
        plain_text = unpadder.update(decrypted_plain_text) + unpadder.finalize()
        plain_text_bytes  = plain_text
        plain_text = plain_text.decode()
        ## load public key

        with open("public_key.der","rb") as key_file:
            public_key = serialization.load_der_public_key(
                key_file.read(),
                backend=default_backend())

        ##  verify the signature
        try:
            public_key.verify(
                Message_rec.signature,
                plain_text_bytes,
                paddings.PSS(
                    mgf=paddings.MGF1(hashes.SHA256()),
                    salt_length=paddings.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print ("verify success!")
        except:
            print('Error in verifying the signature!')
            sys.exit(1)




        print ("Plain text is:", plain_text)
        verify_a = plain_text.split("|")[0]
        verify_b = plain_text.split("|")[1]
        # print ("Decrypted Ga mod p=:",verify_a)
        # print ("Decrypted Gb mod p=:",verify_b)
        # print (alice.public_key)
        # print (Message_rec.gb_mod_p)
        if verify_a == str (alice.public_key) and verify_b == Message_rec.gb_mod_p:
            print ("True")
        else:
            print ("False")

    # def verify_and_login (self, socket, Kas):
    #     Message_send = COMM_MESSAGE()
    #     Message_send.type = COMM_MESSAGE.TYPE.LOGIN
    #     Message_rec = COMM_MESSAGE()
    #     data = socket.recv()
    #     Message_rec.ParseFromString(data)





    def get_name(self):
        return (self.client_name, self.client_password)


if __name__ == '__main__':
    print ("Please type your Username:")
    client_name = input()
    print ("Please type your Password:")
    client_password = input ()
    test_object = Client (client_name, client_password)
    print("The client name and password is", test_object.get_name())
    socket = test_object.connect_to_server()
    puzzle = test_object.puzzle(socket)
    print ("The answer of the puzzle is:", puzzle)
    test_object.session(socket, puzzle)
    # test_object.verify_and_login (socket, Kas)


        # # DH
        # p = 23  # p
        # g = 5  # g
        #
        # a = 6  # a
        # b = 15  # b
        #
        #
        # # Alice Sends Bob A = g^a mod p
        # A = (g ** a) % p
        # print("\n  Alice Sends Over Public Chanel: ", A)
        #
        # # Bob Sends Alice B = g^b mod p
        # B = (g ** b) % p
        # print("\n  Bob Sends Over Public Chanel: ", B)
        # print("\n------------\n")
        # print("Privately Calculated Shared Secret:")
        # # Alice Computes Shared Secret: s = B^a mod p
        # aliceSharedSecret = (B ** a) % p
        # print("    Alice Shared Secret: ", aliceSharedSecret)
        #
        # # Bob Computes Shared Secret: s = A^b mod p
        # bobSharedSecret = (A ** b) % p
        # print("    Bob Shared Secret: ", bobSharedSecret)


#Port
# HOST = '127.0.0.1'  # The server's hostname or IP address
        # PORT = 9090  # The port used by the server
        #
        # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #     s.connect((HOST, PORT))
        #     data = s.recv(1024)
        #
        # print('Received', repr(data))
