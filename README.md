## Chat Application

### Team members:
* Yushen Ni
* Ryan Joshua D'silva

### What is the files
* client.py is the draft of client_login
* server.py is the draft of server_login (amended with serverside db code)
* sample files for reference are included in the reference script folder

### Problem found
* In Login part:
  * Step 1-3: Server need to maintain the connection information of `Client` who wants to login
  * Step 4: What if someone change gb mod p?
            Since tag, signature, authenticate_data not encrypted, what if someone change these?
