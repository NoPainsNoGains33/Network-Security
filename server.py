import socket
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
from message_type_pb2 import COMM_MESSAGE
import zmq

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.connect("tcp://localhost:9090")

Message = COMM_MESSAGE()
while True:
    data = socket.recv()
    Message.ParseFromString(data)

    if Message.type == Message.TYPE.LOGIN:
        N1 = 66
        Message.N1 = N1
        digest = sha256()
        digest.update(str(N1).encode())
        Message.N1_hash = digest.hexdigest()
        socket.send (Message.SerializeToString())

        data = socket.recv()
        Message.ParseFromString(data)


