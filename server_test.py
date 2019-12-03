LOCALHOST = '127.0.0.1'
PORT = 9090

import socketserver



class MyServer(socketserver.BaseRequestHandler):

    # Define handle and the function name MUST be handle
    def handle(self):
        conn = self.request
        print  (conn)
        conn.sendall(bytes("Welcome！\nType q to end the chatting！", encoding='utf-8'))
        while True:
            ret = str(conn.recv(1024), encoding='utf-8')
            if ret == 'q':
                break
            else:
                conn.sendall(bytes("What I received is：" + ret, encoding='utf-8'))
        conn.close()


if __name__ == '__main__':
    server = socketserver.ThreadingTCPServer((LOCALHOST, PORT), MyServer)
    server.serve_forever()

# import  socket
# import threading
#
# server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# server.bind(("127.0.0.1",9090))
# server.listen()
#
# def handle_sock(sock):   #sock 的流程
#     sock.sendall(bytes("Welcome！\nType q to end the chatting！", encoding='utf-8'))
#     while True:
#         ret = str(sock.recv(1024), encoding='utf-8')
#         if ret == 'q':
#             break
#         else:
#             sock.sendall(bytes("What I received is：" + ret, encoding='utf-8'))
#     sock.close()
#
#
# while True:
#     sock, addr = server.accept()  #接受不同client 端的sock .
#     client_thread=threading.Thread(target=handle_sock,args=(sock))  #把sock 加入线程内
#     client_thread.start()  #启动线程
