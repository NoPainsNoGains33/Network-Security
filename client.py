import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from message_type_pb2 import COMM_MESSAGE
class Client():
    client_name = " "
    client_password = " "
    # client_response = " "

    def __init__(self, c_name, c_password):
        self.client_name = c_name
        self.client_password = c_password

    def login(self):
        #Setting up TCP connection
        HOST = '127.0.0.1'  # The server's hostname or IP address
        PORT = 9090  # The port used by the server
        Message_send = COMM_MESSAGE
        Message_send.type = COMM_MESSAGE.Type.LOGIN
        Message_rec = COMM_MESSAGE

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(Message_send.SerializeToString())
            data = s.recv(1024)
            Message_rec.ParseFromString(data)
            digest = hashes.Hash(hashes.SHA256, backend=default_backend())
            for i in range (0,1000):
                digest.upgrate (i)
                if Message_rec.N1_hash == digest.finalize ():
                    break
            # Now, know N1 is i







    def get_name(self):
        return (self.client_name, self.client_password)


if __name__ == '__main__':
    test_object = None
    while True:
        print ("Please type your Username:")
        client_name = input()
        print ("Please type your Password:")
        client_password = input ()
        test_object = Client (client_name, client_password)
        print("The client name and password is", test_object.get_name())
        test_object.login()



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
