import socket
import sys
import time
import base64
import argparse
import os
import json

# import the message type
from message_head_pb2 import MESS
from threading import Thread
# to handle Ctrl+C
from signal import signal, SIGINT

arg_parser = argparse.ArgumentParser(description="Client-side application script to communicate via P2P chat")
arg_parser.add_argument("-sp", type=int, help="Port address for the server", dest="server_port", required=True)
arg_parser.add_argument("-sip", type=str, help="IP address for the server", dest="server_ip", required=True)
arg_parser.add_argument("-u", type=str, help="Username for the client", dest="username", required=True)
args = arg_parser.parse_args()

message_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
message_socket.bind((socket.gethostname(), 0))

# store the list of users on the network when requested from the server
AVAILABLE_USERS = dict()


# use stdout to print output over 'print', to avoid carriage returns in the prompts
def printout(text):
    sys.stdout.write(text)
    sys.stdout.flush()


# signal handler to kill the client
def kill_client(kill_code, frame):
    raise Exception


# advertise that the server is either coming online on the network, or confirm that it is still online
def sign_in():
    client_message = MESS()
    client_message.type = MESS.Type.SIGN_IN
    client_message.payload = args.username
    message_socket.sendto(client_message.SerializeToString(), (args.server_ip, args.server_port))


# method body for the thread to send chat commands
def user_send():
    try:
        # create a protobuf message for chat commands
        command_message = MESS()
        global AVAILABLE_USERS
        while True:
            command = raw_input()
            # command type: list
            # description: retrieve a list of all the clients currently on the network,
            # from the server
            if (command == "list"):
                command_message.type = MESS.Type.LIST
                message_socket.sendto(command_message.SerializeToString(), (args.server_ip, args.server_port))
                continue;
            # command type: send
            # description: send a chat message to another client in the
            # form 'send <peer-name> <message>'
            if (("send" in command)):
                if (command.split()[1] in AVAILABLE_USERS.keys()):
                    command_message.type = MESS.Type.SEND
                    # prepend the message payload, i.e, the message to send, with the sender name
                    command_message.payload = command.replace("send " + command.split()[1], args.username)
                    message_socket.sendto(command_message.SerializeToString(), (
                    AVAILABLE_USERS[command.split()[1]][0], AVAILABLE_USERS[command.split()[1]][1]))
                    printout("+> ")
                    continue;
                # if the peer is no longer in the network, i.e, stale entry in AVAILABLE_USERS
                else:
                    printout("Sorry, this user is not on the network.\n")
                    printout("+> ")
            # if command entered is invalid
            else:
                printout("Sorry, invalid command\n")
                printout("+> ")
    # should catch network exceptions
    except Exception, e:
        print
        "Exception occurred!: " + str(e)
        sys.exit(1)


def user_receive():
    try:
        global AVAILABLE_USERS
        # sign in and register with server when client is booted
        sign_in()
        printout("+> ")
        received_message = MESS()
        while True:
            data, node_address = message_socket.recvfrom(4096)
            received_message.ParseFromString(data)
            # when the client receives a list of available users from the server on bootup
            if (received_message.type == MESS.Type.USER_LIST):
                AVAILABLE_USERS = json.loads(received_message.payload)
                printout("<- Signed In Users: " + ", ".join(AVAILABLE_USERS.keys()) + "\n")
                printout("+> ")
            # when the client sends a message to another peer/client
            if (received_message.type == MESS.Type.SEND):
                sender = received_message.payload.split()[0]
                AVAILABLE_USERS[sender] = node_address
                # prepare the sender id to display along with received mesage
                sender_string = "<From " + str(node_address[0]) + ":" + str(node_address[1]) + ":" + sender + ">:"
                printout("\n<- " + sender_string + received_message.payload.replace(sender, "") + "\n")
                printout("+> ")
            if (received_message.type == MESS.Type.USER_POLL):
                sign_in()
    except Exception, e:
        print
        "Sorry, an error occurred: " + str(e)
        sys.exit(1)


if __name__ == "__main__":
    try:
        # call the signal handler in the main thread
        signal(SIGINT, kill_client)
        # thread to handle received socket messages
        receive_thread = Thread(target=user_receive, args=[])
        # thread to send socket messages
        send_thread = Thread(target=user_send, args=[])
        # start the thread
        receive_thread.start()
        send_thread.start()
        # keep the main thread alive to maintain context and catch the exit signal
        while True:
            time.sleep(0.5)
    # handle the exit condition
    except Exception, e:
        printout("\nClient exited manually.")
        message_socket.close()
        os._exit(0)
