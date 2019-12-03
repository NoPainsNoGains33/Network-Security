import socket
IP = '127.0.0.1'
port = 9090


client_sk = socket.socket()
client_sk.connect((IP, port))
print(str(client_sk.recv(1024), encoding='utf-8'))
while True:
    inp = input("Please type：")
    client_sk.sendall(bytes(inp, encoding='utf-8'))
    if inp == 'q':
        break
    else:
        print(str(client_sk.recv(1024), encoding='utf-8'))

#close the connection
client_sk.close()
