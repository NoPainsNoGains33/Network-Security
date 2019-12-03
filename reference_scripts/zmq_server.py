import zmq, time

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.connect("tcp://localhost:5555")

while True:
    message = socket.recv()
    print (f"Received request: {message}")

    time.sleep(1)

    socket.send(b"World")
