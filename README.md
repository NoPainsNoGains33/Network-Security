## Cryptographically Secure Instant Messaging Application

### Team members:
* Yushen Ni
* Ryan Joshua D'silva

### List of files included:
* client.py is the client-side application
* server.py is the severside application
* Private and public server keys for the server application
* server_creds.json, including the serverside data of registered users
* message_type.proto, to be compiled to provide the message container template used for
  communication in this project

### Requirements to run these programs:
* Aside from the standard python libraries, we need the `cryptography hazmat` library and the
  `diffiehellman` library.
* The supporting files, that is, the keys and server_creds.json need to be in the same
  directory
    
### Shortcomings
* The 'logout' feature was unable to be satisfactorily completed and is unavailable in the
   implementation
* The application is only designed to run over localhost, that is, all instances on the same
   machine.
* New logins do not reflect in the list of currently online users that have already requested
  the list before.

### Instructions:
* The server should start up and run fine by itself without further input
* The client requires a username and password login.
* The available usernames and passwords are:
	* Username: Ryan, password: yushen
	* Username: Yushen, password: ryan
	* Username: Alice, password: 123
	* Username: Bob, password 123
* Type 'list' after logging in to obtain the list of currently online users
* Type 'Talk to <username>' to talk to said username and initiate the mutual authentication
* Type 'send <username> <message>' to talk to a user you have already connected to.
* A Ctrl+C should terminate the application.
