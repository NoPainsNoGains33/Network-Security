import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from message_type_pb2 import COMM_MESSAGE
import zmq

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.connect("tcp://localhost:9090")

Message = COMM_MESSAGE()
data = socket.recv()
Message.ParseFromString(data)

if Message.type == Message.TYPE.SIGNIN:
    N1 = 100
    Message.N1 = N1
    digest = hashes.Hash(hashes.SHA256, backend=default_backend())
    digest.upgrate(N1)
    Message.N1_hash = digest.finalize()
    socket.send (Message.SerializeToString())

