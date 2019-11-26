import zmq

trial = zmq.Context()


socket = trial.socket(zmq.REQ)
socket.bind("tcp://*:5555")

for request in range(10):
    print(f"Request number {request}")
    socket.send(b"Hello")

    message = socket.recv()
    print(f"Received reply: {request}, {message}")
