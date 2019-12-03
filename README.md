## Chat Application

### Team members:
* Yushen Ni
* Ryan Joshua D'silva

### What is the files
* client.py is the draft of client_login
* server.py is the draft of server_login (amended with serverside db code)
* sample files for reference are included in the reference script folder

### Problem found
* Server: We need to shut down the thread if no response for some time, especially in login
* Client: We need to raise exceptions when Server not respond for some time
* In Login part:
  * Step 1-3: Server need to maintain the connection information of `Client` who wants to login
  * Step 4: 
    1. What if someone change gb mod p?
    2. Since iv, tag, signature, authenticate_data not encrypted, what if someone change these?
    
 ### Notice
 * I have changed the puzzle from 0-26bit in total 27 bits into 20bits, which balance the running time and the difficulty of the puzzle
 * In the server demo, only can verify `username` is "Yushen" and `password` is "123"
