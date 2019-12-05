import socket
import sys
import time
import os
import threading
from getpass import getpass
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
        self.authenticate_data = b'Final Project'
        self.Message_send = COMM_MESSAGE()
        self.Message_rec = COMM_MESSAGE()

    def connect_to_server(self):
        self.socket_to_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', 9090)
        self.socket_to_server.connect(server_address)
        # context = zmq.Context()
        # self.socket = context.socket(zmq.REQ)
        # self.socket.bind("tcp://127.0.0.1:9090")

    def send_message(self):
        self.socket_to_server.sendall(self.Message_send.SerializeToString())

    def receive_message(self):
        data = self.socket_to_server.recv(4096)
        self.Message_rec.ParseFromString(data)

    def verify_timestamp(self, timestamp):
        time_now = int(time.time())
        plain_text_timestamp = timestamp.decode()
        plain_text_timestamp = int(plain_text_timestamp)
        if (time_now - plain_text_timestamp < 60):
            print("Timestamp verified!")
            return True
        else:
            print("Failed in Timestamp!")
            return False

    def encryption(self, plain_text):
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

    def decryption_with_timestamp(self):
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

    def decryption_of_ticket_with_timestamp(self, cipher_text, tag):
        #  AES  decryption
        # print ("Kas:", self.Kas)
        # print ("IV:",self.iv)
        # print ("Ticket:", cipher_text)
        # print ("Ticket_tag:", tag)
        decryptor = Cipher(algorithms.AES(self.Kas), modes.GCM(self.iv, tag),
                           backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(self.authenticate_data)
        decrypted_plain_text = decryptor.update(cipher_text) + decryptor.finalize()

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
            print ("This ticket is not fresh!")
            sys.exit(1)

    def puzzle(self):
        self.Message_send.type = COMM_MESSAGE.TYPE.LOGIN

        #  send the first message to announce the server: "I want to log in"
        self.send_message()

        # receive from the server: puzzle
        self.receive_message()

        for i in range(0, int('100000', 16)):
            i_hex = hex(i)[2:]
            answer = i_hex + self.Message_rec.message
            digest = sha256()
            digest.update(answer.encode())
            if digest.hexdigest() == self.Message_rec.N1_hash:
                break
        self.Message_send.N1 = answer
        print("Puzzle solved and the answer is:", i_hex)

    # set up the session key of client
    def session(self):
        alice = DiffieHellman(group=5, key_length=200)
        alice.generate_public_key()
        self.Message_send.message = str(alice.public_key)
        # send puzzle answer and ga mod p
        self.send_message()

        # receive the session key of server
        self.receive_message()

        alice.generate_shared_secret(int(self.Message_rec.gb_mod_p))
        # set up the session key Kas
        self.Kas = str(alice.shared_secret)[:16].encode()
        self.iv = self.Message_rec.iv
        print("Shared secret is:", int.from_bytes(self.Kas, sys.byteorder))

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

    def login(self):
        message = self.client_name + "|" + self.client_password
        message = message.encode()
        timestamp = str(int(time.time())).encode()
        plain_text = message + timestamp
        # Encrypt the data
        self.encryption(plain_text)

        # Send the data
        self.send_message()

        # Receive the data
        self.receive_message()

        # Decrypt the data
        plain_text = self.decryption_with_timestamp()
        plain_text = plain_text.decode()
        print(plain_text)
        if (plain_text == 'Fail'):
            sys.exit(1)
        else:
            self.port_for_listening = int(plain_text.split("|")[1])

    def client_to_server_login(self):
        test_object.connect_to_server()
        test_object.puzzle()
        test_object.session()
        test_object.login()
        # self.socket_to_server.close()

    def get_name(self):
        return self.client_name, self.client_password

    def bind_for_listening(self):
        self.socket_to_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_to_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket_to_client.bind(("127.0.0.1", self.port_for_listening))

    def handle_sock(self, sock, addr):  # sock 的流程
        ##############################
        #### Handle a new request#####
        ####                     #####
        ##############################
        while True:
            data = sock.recv(4096)
            print ("I have received a new message!")
            MessageRec = COMM_MESSAGE()
            MessageRec.ParseFromString(data)
            if (MessageRec.type == COMM_MESSAGE.TYPE.CLIENT_TO_CLIENT):
                plain_text = self.decryption_of_ticket_with_timestamp(MessageRec.ticket, MessageRec.ticket_tag)
                plain_text = plain_text.decode()
                src = plain_text.split(" ")[0]
                self.socket_list[src] = []
                self.socket_list[src].append (sock)
                kab_temp = plain_text.split(" ")[1].encode()
                iv_temp = plain_text.split(" ")[2].encode()
                plain_text = self.decryption_with_timestamp_in_client(MessageRec, kab_temp, iv_temp)
                plain_text = plain_text.decode()

                N1 = int(plain_text)
                y = os.urandom(8)
                x = y.hex()
                N2 = int(x, 16)
                plain_text = (str(N1-1)+ " " + str(N2)).encode()+ str(int(time.time())).encode()
                # .encode() + " ".encode + str(N2).encode()

                MessageSend = COMM_MESSAGE()

                bob = DiffieHellman(group=5, key_length=200)
                bob.generate_public_key()
                MessageSend.gb_mod_p = str(bob.public_key)
                MessageSend = self.encryption_in_client(MessageSend, kab_temp, iv_temp, plain_text)
                sock.sendall(MessageSend.SerializeToString())

                MessageRec = COMM_MESSAGE()
                data = sock.recv(4096)
                MessageRec.ParseFromString(data)

                plain_text = self.decryption_with_timestamp_in_client(MessageRec, kab_temp, iv_temp)
                N2_rec = int(plain_text.decode())
                if N2-1 == N2_rec:
                    bob.generate_shared_secret(int(MessageRec.message))
                    self.socket_list[src].append(str(bob.shared_secret)[:16].encode())
                    temp = os.urandom(16)
                    iv = temp.hex()[:16].encode()
                    self.socket_list[src].append(iv)

                    plain_text = ("Confirm " + self.client_name).encode() + str(int(time.time())).encode()
                    MessageSend = COMM_MESSAGE()
                    MessageSend.iv = iv
                    MessageSend = self.encryption_in_client(MessageSend, self.socket_list[src][1], iv, plain_text)
                    sock.sendall(MessageSend.SerializeToString())

                    MessageRec = COMM_MESSAGE()
                    data = sock.recv(4096)
                    MessageRec.ParseFromString(data)


                    plain_text = self.decryption_with_timestamp_in_client(MessageRec, self.socket_list[src][1], iv)
                    plain_text = plain_text.decode()
                    if plain_text.split(" ")[0] == "Confirm" and plain_text.split(" ")[1] == src:
                        print("I have succeed in setting up connection with", src, "with session key:", self.socket_list[src][1])
                        print("We use this socket to chatting:", sock)
                    else:
                        print ("The adversary modify the CONFIRM message")
                else:
                    print ("N2 puzzle wrong!")
                    sys.exit(1)
            else:
                plain_text = self.decryption_with_timestamp_in_client(MessageRec, self.socket_list[src][1], self.socket_list[src][2])
                plain_text = plain_text.decode()
                print ("From", src,":", plain_text)

    def listen(self, temp):
        self.socket_to_client.listen()
        # print ("I have succeed in start listening socket")
        while True:
            sock, addr = self.socket_to_client.accept()  # 接受不同client 端的sock .
            # print ("I received a new socket request from", sock)
            # self.handle_sock(sock, addr)
            client_thread = threading.Thread(target=self.handle_sock, args=(sock, addr))  # 把sock 加入线程内
            client_thread.start()  # 启动线程

    def client_to_client_send (self, dest, message):
        MessageSend = COMM_MESSAGE()
        MessageSend.type = COMM_MESSAGE.TYPE.MESSAGE
        plain_text =  message.encode() + str(int(time.time())).encode()

        # AES encryption
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plain_text)
        padded_data += padder.finalize()
        plain_text_padded = padded_data
        ## GCM Mode
        cipher = Cipher(algorithms.AES(self.socket_list[dest][1]), modes.GCM(self.socket_list[dest][2]), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(self.authenticate_data)
        cipher_text = encryptor.update(plain_text_padded) + encryptor.finalize()
        MessageSend.cipher_text = cipher_text
        MessageSend.tag = encryptor.tag

        self.socket_list[dest][0].sendall(MessageSend.SerializeToString())
        print ("I have sent message to",dest)

    def decryption_with_timestamp_in_client(self, MessageRec, Kab, ivtemp):
        #  AES  decryption
        decryptor = Cipher(algorithms.AES(Kab), modes.GCM(ivtemp, MessageRec.tag),
                           backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(self.authenticate_data)
        decrypted_plain_text = decryptor.update(MessageRec.cipher_text) + decryptor.finalize()

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

    def encryption_in_client(self, Message, Kab, ivtemp, plain_text):
        # AES encryption
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plain_text)
        padded_data += padder.finalize()
        plain_text_padded = padded_data
        ## GCM Mode
        cipher = Cipher(algorithms.AES(Kab), modes.GCM(ivtemp), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(self.authenticate_data)
        cipher_text = encryptor.update(plain_text_padded) + encryptor.finalize()
        Message.cipher_text = cipher_text
        Message.tag = encryptor.tag
        return Message

    def client_setup_connection (self, dest):
        client_sk = socket.socket()
        client_sk.connect(('127.0.0.1', int(self.user_online[dest][1])))
        self.socket_list[dest] = []
        self.socket_list[dest].append (client_sk)

        #########################
        ### Set up         ######
        ### the connection ######
        #########################
        MessageSend = COMM_MESSAGE()
        MessageRec = COMM_MESSAGE ()
        MessageSend.type = COMM_MESSAGE.TYPE.CLIENT_TO_CLIENT
        MessageSend.ticket = self.user_online[dest][4]
        MessageSend.ticket_tag = self.user_online[dest][5]
        print (MessageSend.ticket)
        print (MessageSend.ticket_tag)
        kabtemp = self.user_online[dest][2].encode()
        ivtemp = self.user_online[dest][3].encode()
        y = os.urandom(8)
        x = y.hex()
        N1 = int(x, 16)
        plain_text  = str(N1).encode() + str(int(time.time())).encode()
        MessageSend = self.encryption_in_client (MessageSend, kabtemp, ivtemp, plain_text)

        self.socket_list[dest][0].sendall (MessageSend.SerializeToString())

        data = self.socket_list[dest][0].recv(4096)
        MessageRec.ParseFromString(data)

        plain_text = self.decryption_with_timestamp_in_client  (MessageRec, kabtemp, ivtemp)
        plain_text = plain_text.decode()
        N1_rec = int(plain_text.split(" ")[0])
        if N1-1 == N1_rec:
            MessageSend = COMM_MESSAGE()
            ### Set up the new Kab ###
            alice = DiffieHellman(group=5, key_length=200)
            alice.generate_public_key()
            MessageSend.message = str(alice.public_key)
            alice.generate_shared_secret(int(MessageRec.gb_mod_p))
            # set up the session key Kas
            self.socket_list[dest].append(str(alice.shared_secret)[:16].encode())
            N2_rec = int(plain_text.split(" ")[1])
            N2_send = N2_rec - 1
            plain_text = str (N2_send).encode() + str(int(time.time())).encode()
            MessageSend.iv = self.user_online[dest][3].encode()
            MessageSend = self.encryption_in_client (MessageSend, kabtemp, ivtemp, plain_text)

            self.socket_list[dest][0].sendall(MessageSend.SerializeToString())

            data = self.socket_list[dest][0].recv(4096)
            MessageRec.ParseFromString(data)

            plain_text = self.decryption_with_timestamp_in_client(MessageRec, self.socket_list[dest][1], MessageRec.iv)
            plain_text = plain_text.decode()
            if plain_text.split(" ")[0] == "Confirm" and plain_text.split(" ")[1] == dest:
                self.socket_list[dest].append(MessageRec.iv)
                plain_text = ("Confirm " + self.client_name).encode() + str(int (time.time())).encode()
                MessageSend = COMM_MESSAGE()
                MessageSend.iv = self.socket_list[dest][2]
                MessageSend = self.encryption_in_client (MessageSend, self.socket_list[dest][1],self.socket_list[dest][2], plain_text)
                self.socket_list[dest][0].sendall(MessageSend.SerializeToString())
                print ("I have succeed in setting up connection with", dest, "with session key:", self.socket_list[dest][1])
                print("We use this socket to chatting:", self.socket_list[dest][0])
            else:
                print ("Set up connection with", dest, "failed!")
                sys.exit(1)

        else:
            print ("N1 verify failed!")
            sys.exit(1)

    def talk_with_server(self):
        ## In user_online, it stores users online with port, Kab_temp, ticket
        self.user_online = {}
        ## In socket_list, it stores all socket, Kab, iv Client are talking to
        self.socket_list = {}
        listen_thread = threading.Thread(target=test_object.listen, args=(1,))
        listen_thread.start()

        while (True):
            self.Message_send = COMM_MESSAGE()
            command = input()
            if (command == "list"):
                self.Message_send.type = COMM_MESSAGE.TYPE.LIST
                plain_text = command.encode() + str(int(time.time())).encode()
                self.encryption(plain_text)
                self.send_message()
                self.receive_message()
                plain_text = self.decryption_with_timestamp()
                plain_text = plain_text.decode()
                print("This users are online now:", plain_text)
                # update the online user
                for temp in plain_text.split(" "):
                    if temp not in self.user_online.keys():
                        self.user_online[temp] = []
            else:
                if (len(command.split(" ")) == 3 and "Talk to" in command):
                    dest = command.split(" ")[2]
                    if (dest != self.client_name):
                        if dest in self.socket_list.keys():
                            print("You are now connected with",dest, "Just use 'Send' command!")
                            continue
                        if (dest not in self.user_online.keys()):
                            print(dest, "is not online now!")
                            continue
                        else:
                            self.Message_send.type = COMM_MESSAGE.TYPE.LIST_PART2
                            plain_text = command.encode() + str(int(time.time())).encode()
                            self.encryption(plain_text)
                            self.send_message()

                            self.Message_rec = COMM_MESSAGE()
                            self.receive_message()

                            decryptor = Cipher(algorithms.AES(self.Kas), modes.GCM(self.iv, self.Message_rec.tag),
                                               backend=default_backend()).decryptor()
                            decryptor.authenticate_additional_data(self.authenticate_data)
                            decrypted_plain_text = decryptor.update(self.Message_rec.cipher_text) + decryptor.finalize()

                            # unpad
                            unpadder = padding.PKCS7(128).unpadder()
                            plain_text = unpadder.update(decrypted_plain_text) + unpadder.finalize()

                            ticket = self.Message_rec.ticket
                            ticket_tag = self.Message_rec.ticket_tag
                            plain_text = plain_text.decode()
                            print (plain_text)
                            if dest == plain_text.split(" ")[0]:
                                for item in plain_text.split(" "):
                                    self.user_online[dest].append(item)
                                self.user_online[dest].append(ticket)
                                self.user_online[dest].append(ticket_tag)
                                print ("Now, u can talk to", dest, "whose port is", int(self.user_online[dest][1]))
                            else:
                                print ("Someone change the person I want to talk to!")
                                continue
                    else:
                        print ("Sorry, you can't talk to yourself!")
                        continue
                else:
                    if (command.split(" ")[0] == 'Send' and len(command.split(" ")) >=3):
                        dest = command.split(" ")[1]
                        message = command.split(" ",2)[2]
                        if dest in self.socket_list.keys():
                            self.client_to_client_send(dest, message)
                        else:
                            if (dest not in self.user_online.keys()):
                                print ("Sorry, you can't send message to whom is not online!")
                                continue
                            else:
                                if self.user_online[dest] == []:
                                    print ("You must ask server for ticket first!")
                                    continue
                                else:
                                    if dest not in self.socket_list.keys():
                                        self.client_setup_connection (dest)
                                    self.client_to_client_send(dest, message)
                    else:
                        print ("Please type a correct format!")
                        continue
            # print("Now, I have stored these users with/without port:", self.user_online)




if __name__ == '__main__':
    client_name = input("Please type your username:")
    client_password = getpass("Please type your password:")
    test_object = Client(client_name, client_password)
    print("The client name and password is", test_object.get_name())
    test_object.client_to_server_login()
    print("Now, send message!")
    test_object.bind_for_listening()
    test_object.talk_with_server()

# send_thread = threading.Thread(target=test_object.send, args=(1,))
# send_thread.start()
