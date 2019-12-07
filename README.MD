# Peer to Peer Encrypted Messaging Application #

## Starting the server ##

To start clients from the root directory (inside <finalproject-birn-rush>) you can run `python server.py (args)`. 

### args ###
All arguments for the server are optional
1. `-priv`: Specify the private key to use for the server. If not specified will use the key in /keys.
2. `-pub`: specify the public key to use for the server. Must be used with -priv. If not specified will use the public key in /keys.
3. `-port`: Specify the port on which to run the server. If none the server will default to 15001


## Starting clients ##

To start clients from the root directory (inside <finalproject-birn-rush>) you can run `python client.py (args)`. This will prompt a user to log in with first a username, and then a password. 

#### args ####
All arguments for the client are optional
1. `-pub`: Specify the public key of the server. If not specified it will use the same public key that the server loads from /keys.
2. `-ip`: specify the server ip to connect to. If not specified will use localhost
3. `-port`: Specify the server port on which to connect to. If not specified will use 15001.

### Client functionality ###

**send (user) (message)**
* This function send a specified user a specified message

**list**
* This function lists all users logged into the server

**logout**
* This function can be used to logout of the server. Ctrl-c and any handled errors will also cause the user to log out if they are logged in.


## Registered Users and Passwords ##

_All registered users and passwords are in the format user:password. They are case sensitive._
1. Bob:password
2. tyler:password
3. clara:password2
4. robert:password2
