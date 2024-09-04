Secure Chat App

A peer-to-peer application (secure_chat_app) for chatting which uses TLS 1.2 and TCP as the underlying protocols for secure and reliable communication.  Note that the secure_chat_app works like HTTPS except that here it’s a peer-to-peer paradigm where Alice plays the role of the client and Bob plays the role of the server and vice versa.

Task 1: Start a Downgrade attack by Trudy by blocking the chat_START_SSL control message from Alice (Bob) to Bob (Alice). 

Task 2: Active MITM attack by Trudy to tamper the chat communication between Alice and Bob. For this task also, you can assume that Trudy poisoned the /etc/hosts file of Alice (Bob) and replaced the IP address of Bob (Alice) with that of her.

