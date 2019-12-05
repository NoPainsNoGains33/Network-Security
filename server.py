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
import sys
import os
import socket
import json
import logging
import string
from random import choice
from threading import Thread
from datetime import datetime
from sys import stdout
from diffiehellman.diffiehellman import DiffieHellman


class ValidationError(Exception):
    pass


class Server():
    identities = None
    socket_from_client = None
    logger = None
    open_sockets = None

    def shutdown_application(self):
        self.logger.error(f"Closing entire application from this thread")
        #crit_message = COMM_MESSAGE()
        ## crit_message.type = crit_message.TYPE.ERROR
        #crit_message.message = str("SERVER SHUTDOWN")
        for socket in self.open_sockets:
            #socket.sendall(crit_message.SerializeToString())
            socket.close()
        self.socket_from_client.close()
        del self.identities
        os._exit(0)

    def get_logger(self):
        logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.DEBUG,
                            handlers=[
                                logging.FileHandler(filename=datetime.now().strftime("%H_%M_%d_%m_%Y_") + "server.log"),
                                logging.StreamHandler(stdout)])
        self.logger = logging.getLogger()

    def load_user_data(self):
        with open("server_creds.json", "r") as creds:
            self.identities = json.loads(creds.read())
        for user in self.identities.keys():
            self.identities[user]["is_online"] = False
            self.identities[user]["ip_address"] = None
            self.identities[user]["serverclient_key"] = None
            self.identities[user]["serverclient_iv"] = None

    def set_server_socket(self):
        self.socket_from_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_from_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serveraddress = ('localhost', 9090)
        self.socket_from_client.bind(serveraddress)
        self.socket_from_client.listen(1)
        return self.socket_from_client

    def receive_message(self, connection):
        message_container = COMM_MESSAGE()
        data, temp = connection.recvfrom(4095)
        message_container.ParseFromString(data)
        return message_container

    def generate_n1(self):
        N1 = os.urandom(16)
        return N1.hex()

    def get_hash(self, string_to_hash):
        digest = digest = sha256()
        digest.update(string_to_hash.encode())
        return digest.hexdigest()

    def get_padded_data(self, data_to_pad):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_to_pad)
        padded_data += padder.finalize()
        return padded_data

    def get_unpadded_data(self, data_to_unpad):
        unpadder = padding.PKCS7(128).unpadder()
        plain_text = unpadder.update(data_to_unpad) + unpadder.finalize()
        return plain_text

    def get_ciphertext_message(self, cipher_params, plaintext, message):
        cipher = Cipher(algorithms.AES(cipher_params["key"]), modes.GCM(cipher_params["iv"]), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(cipher_params["auth_string"])
        cipher_text = encryptor.update(plaintext) + encryptor.finalize()
        message.cipher_text = cipher_text
        message.tag = encryptor.tag
        return message

    def get_plaintext_from_message(self, cipher_params, message):
        decryptor = Cipher(algorithms.AES(cipher_params["key"]), modes.GCM(cipher_params["iv"], message.tag),
                           backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(cipher_params["auth_string"])
        decrypted_plain_text = decryptor.update(message.cipher_text) + decryptor.finalize()
        return decrypted_plain_text

    def get_plaintext_ts(self, decrypted_string):
        message_string = decrypted_string[0:len(decrypted_string) - 10]
        ts_string = decrypted_string[-10:]
        return (message_string.decode(), ts_string.decode())

    def verify_timestamp(self, timestamp_string):
        message_timestamp = int (timestamp_string)
        if ((int(time.time()) - message_timestamp) > 60):
            raise ValidationError("Timestamp is incorrect!")
        # if ((int(time.time()) - message_timestamp) < 60):
        #     return True
        # return False

    def get_timestamp(self):
        return str(int(time.time()))

    def connection_ini_proto(self, message, connection_from_client):
        try:
            ####################################
            ## Message 1: Send and receive N1 ##
            ####################################
            self.open_sockets.append(connection_from_client)
            N1 = self.generate_n1()
            message.N1_hash = self.get_hash(N1)
            message.message = N1[5:]
            connection_from_client.sendall (message.SerializeToString())
            message = self.receive_message(connection_from_client)
            self.logger.debug(f"{connection_from_client.getpeername()}:: Received N1")
            if message.N1 == N1:
                self.logger.debug(f"{connection_from_client.getpeername()}:: Puzzle resolved!")
            else:
                self.logger.error(f"{connection_from_client.getpeername()}:: Puzzle not resolved!")
                raise ValidationError(f"Puzzle not resolved!")
            ##################################################
            ## Message 2: Establish session key with client ##
            ##################################################
            bob = DiffieHellman(group=5, key_length=200)
            bob.generate_public_key()
            message.gb_mod_p = str (bob.public_key)
            bob.generate_shared_secret(int (message.message))
            Kas =  str(bob.shared_secret)[:16].encode()
            print ("Shared secret is:", int.from_bytes (Kas, sys.byteorder))
            self.logger.debug(f"{connection_from_client.getpeername()}:: Shared secret is:{int.from_bytes (Kas, sys.byteorder)}")
            message.gb_mod_p = str (bob.public_key)
            
            #### loading private key
            with open("private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend())
            
            #### encryption
            plain_text_sign = message.message + "|" + message.gb_mod_p
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
            message.iv = iv
            plain_text_padded = self.get_padded_data(plain_text)

            authenticate_data = b'Final Project' 
            # Cipher parameters to facilitate encryption and decryption
            cipher_params = {"key":Kas, "iv": iv, "auth_string": authenticate_data}

            message_to_send = self.get_ciphertext_message(cipher_params, plain_text_padded, message)
            connection_from_client.sendall(message_to_send.SerializeToString())
            ###########################################
            ## Message 3: Validate login credentials ##
            ###########################################
            message = self.receive_message(connection_from_client)
            decrypted_plain_text = self.get_plaintext_from_message(cipher_params, message)
            plain_text = self.get_unpadded_data(decrypted_plain_text)
            text_string, timestamp_string = self.get_plaintext_ts(plain_text)
            # if self.verify_timestamp(timestamp_string):
            #     self.logger.debug(f"{connection_from_client.getpeername()}:: Timestamp verified!")
            # else:
            #     self.logger.error(f"{connection_from_client.getpeername()}:: Timestamp failed!")
            #     raise ValidationError(f"Timestamp failed on credential verification")
            self.verify_timestamp(timestamp_string)
            username  =  text_string.split("|")[0]
            password = text_string.split("|")[1]
            verify = "Fail"
            if username in self.identities.keys():
                pass_hash = self.get_hash(password + self.identities[username]["salt"])
                if pass_hash == self.identities[username]["passhash"]:
                    verify = "Success|" + str(self.identities[username]["port"])
            if verify == "Fail":
                raise ValidationError(f"Incorrect password or username!")

            plain_text =  verify.encode()
            timestamp = self.get_timestamp().encode()
            plain_text = plain_text + timestamp
            
            plain_text_padded = self.get_padded_data(plain_text)

            message_to_send = self.get_ciphertext_message(cipher_params, plain_text_padded, message)
            connection_from_client.sendall(message_to_send.SerializeToString())
            self.identities[username]["is_online"] = True
            self.identities[username]["ip_address"] = connection_from_client.getpeername()[0]
            self.identities[username]["serverclient_key"] = Kas
            self.identities[username]["serverclient_iv"] = iv

        except (ValidationError, Exception) as critical_error:
            self.logger.error(f"{connection_from_client.getpeername()}:: {critical_error}")
            message.type = message.TYPE.ERROR
            message.message = str(critical_error)
            connection_from_client.sendall(message.SerializeToString())
            return

        except (KeyboardInterrupt) as fatal_error:
            self.shutdown_application()

        while True:
            try:
                message = self.receive_message(connection_from_client)
                decrypted_plain_text = self.get_plaintext_from_message(cipher_params, message)
                ## Add a handler here to handle terminated connections sending bad data
                plain_text = self.get_unpadded_data(decrypted_plain_text)
                text_string, timestamp_string = self.get_plaintext_ts(plain_text)
                ########################
                ## Message Type: LIST ##
                ########################
                if message.type == message.TYPE.LIST:
                    self.logger.debug(f"{connection_from_client.getpeername()}: Received LIST message")
                    self.verify_timestamp(timestamp_string)
                    if (text_string == "list"):
                        data_string = " ".join(name for name in self.identities.keys() if self.identities[name]["is_online"])
                        self.logger.debug(f"{connection_from_client.getpeername()}: Sending online user list\n\t[{data_string}]")
                        response_string = data_string.encode() + self.get_timestamp().encode()
                        padded_response_string = self.get_padded_data(response_string)
                        message_to_send = self.get_ciphertext_message(cipher_params, padded_response_string, message)
                        connection_from_client.sendall(message_to_send.SerializeToString())
                    else:
                        raise ValidationError("The list command is incorrect")
                ##########################
                ## Message Type: LIST_2 ##
                ##########################
                if message.type == message.TYPE.LIST_PART2:
                    self.logger.debug(f"{connection_from_client.getpeername()}: Received LIST_2 message")
                    user = text_string.split(" ")[2]
                    self.verify_timestamp(timestamp_string)
                    if (self.identities[user]["is_online"]):
                        ## Generate a new Kab
                        kab = os.urandom(16)
                        kab_string = kab.hex()[:16]
                        ## Generate a new iv
                        ticket_iv = self.identities[user]["serverclient_iv"]
                        print (ticket_iv)
                        ivtemp =os.urandom(16)
                        ticket_iv_string = ivtemp.hex()[:16] ### iv ab
                        ## Get serverclient key for the user requested
                        ticket_enc_key = self.identities[user]["serverclient_key"]
                        ## Create new encryption for the ticket
                        ## Key will be Kbs
                        ## Get encrypted ticket
                        #########################################
                        ticket_cipher = Cipher(algorithms.AES(ticket_enc_key), modes.GCM(ticket_iv),
                                               backend=default_backend())
                        ticket_encryptor = ticket_cipher.encryptor()
                        ticket_encryptor.authenticate_additional_data(cipher_params["auth_string"])
                        ticket_string = " ".join([username, kab_string, ticket_iv_string, self.get_timestamp()])
                        ticket_string = ticket_string.encode()
                        padded_ticket_string = self.get_padded_data(ticket_string)
                        ticket_ciphertext = ticket_encryptor.update(padded_ticket_string) + ticket_encryptor.finalize()
                        #############################################
                        data_string = " ".join([user, str(self.identities[user]["port"]), kab_string, ticket_iv_string])
                        response_string = data_string.encode()                        
                        self.logger.debug(f"{connection_from_client.getpeername()}: Completing mutual authentication")
                        padded_response_string = self.get_padded_data(response_string)
                        message_to_send = self.get_ciphertext_message(cipher_params, padded_response_string, message)
                        message_to_send.ticket = ticket_ciphertext
                        message_to_send.ticket_tag = ticket_encryptor.tag
                        # print("Kas:", ticket_enc_key )
                        # print("IV:", ticket_iv)
                        # print ("Ticket:", message_to_send.ticket)
                        # print ("Ticket_tag: ", message_to_send.ticket_tag)
                        connection_from_client.sendall(message_to_send.SerializeToString())
                    else:
                        raise ValidationError(f"User {user} not found online!")
                ##########################
                ## Message Type: LOGOUT ##
                ##########################
                if message.type == message.TYPE.LOGOUT:
                    self.logger.debug(f"{connection_from_client.getpeername()}: Received LOGOUT message")
                    self.verify_timestamp(timestamp_string)
                    if (text_string == "logout"):
                        self.identities[username]["is_online"] = False
                        data_string = "confirmed"
                        self.logger.debug(f"{connection_from_client.getpeername()}: Logging out")
                        response_string = data_string.encode() + self.get_timestamp().encode()
                        padded_response_string = self.get_padded_data(response_string)
                        message_to_send = self.get_ciphertext_message(cipher_params, padded_response_string, message)
                        connection_from_client.sendall(message_to_send.SerializeToString())
                    else:
                        raise ValidationError("Logout not possible")

            except (ValueError) as auth_tag_error:
                self.logger.error(f"{connection_from_client}:: Connection closed abruptly, {auth_tag_error}")
                return

            except (Exception, ValidationError) as critical_error:
                self.logger.error(f"{connection_from_client}:: {critical_error}")
                message.type = message.TYPE.ERROR
                message.message = str(critical_error)
                connection_from_client.sendall(message.SerializeToString())
                continue

            except (KeyboardInterrupt) as fatal_error:
                self.shutdown_application()


    def __init__(self):
        try: 
            self.open_sockets = list()
            self.get_logger()
            self.load_user_data()
            self.logger.debug(f"Server socket set: {self.set_server_socket()}")
            # self.open_sockets.append(self.socket_from_client)
            while True:
                connection_from_client, client_address = self.socket_from_client.accept()
                message = self.receive_message(connection_from_client)
                if message.type == message.TYPE.LOGIN:
                    self.logger.debug(f"Received login message from {client_address}")
                    login_thread = Thread(target=self.connection_ini_proto, args=(message, connection_from_client))
                    self.logger.debug(f"Starting login protocol thread for {client_address}")
                    login_thread.start()
                    continue

        except (KeyboardInterrupt) as fatal_exception:
            self.logger.critical("Program exiting, closing main socket!")
            self.shutdown_application()


if __name__ == '__main__':
    server = Server()
