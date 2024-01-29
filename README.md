

Two parties communicate with each other securely and confidentially


- The sender generates a key and shares it with the receiver using the Diffie Hellman key sharing method.
- The sender then encrypts the text to be sent with DES, signs it with RSA, and transmits it to the receiver.
- At this stage, the hash information of the encrypted message is obtained, the summary information is encrypted to create a signature using the public key method, and the cipher text and signature are sent to the recipient.
- On the receiver side, it is verified that the incoming message comes from the sender and the message is obtained by decrypting it with the shared key and symmetric method.


DES symmetric encryption, RSA signing, MD5 hash function and Diffie Hellman key exchange algorithms were used for these operations.
