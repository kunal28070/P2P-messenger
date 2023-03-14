#NODE 2
import socket
import threading
#import time
#import getpass #not being used anymore bc the password's showing on the screen
import hashlib
from cryptography.fernet import Fernet

# defining the host and port for the P2P network
#HOST = '10.6.6.34'
HOST = 'localhost'
PORT = 9998

# list to store the connected peers
peers = []

# password
PASSWORD = 'mypassword'
# aking for password authentication
#    client_socket.send(b"Please enter password: ")
#    password = client_socket.recv(1024).decode().strip()
#
#    # hashing it
#    hashed_password = hashlib.sha256(password.encode()).hexdigest()
#
##    # checking if the hashed password matches the stored password
#    if hashed_password != "$2y$04$Jod9V9MqiBzw3ABqexLCdOhkP1XEW4E5i/2wcLwrY.eeQ0CxURR1m":
#        client_socket.send(b"Invalid password. Closing connection.")
#        client_socket.close()
#        return

# prompt user for pswd
def getpassword():
    abc = input(b"Please enter password: ")

    # hashing algorithm
    hashed_password =hashlib.sha256(abc.encode('utf-8')).hexdigest()
    return hashed_password

# this fn handles incoming connections from peers -
def peerconn(conn, addr):
    #print(f"\nPEEROCNn EXECUTING")
    global peers
    # adding the new peer to the list of connected peers
    peers.append(conn)
    print(f"\nNew peer connected: {addr}")
    while True:
        # rcving data from the peer
        #print(f"\nData being received from the peer in while loop")
        data = conn.recv(1024)
        if not data:
            # remove the peer from the list of connected peers if no data received
            peers.remove(conn)
            print(f"Peer disconnected: {addr}")
            break
        # decrypting the received data using the reverse cipher
        decrypted_data = data.decode()[::-1]
        #print(f"\nData being decoded")
        # broadcasting the decrypted data to all other connected peers
        for peer in peers:
            if peer != conn: #removed a !=
                # rencrypting the data using the reverse cipher before sending it to the peer
                peer.send(decrypted_data.encode()[::-1])
                #print(f"\nData being encrypted before sending")
        break #might fix?

# function to listen for incoming connections from peers
def listen4peers():
    #print(f"\nLISTEN4PEERS EXECUTING")
    global peers
    # creating a new socket and bind it to the host and port
    #print(f"\ncreating new socket to be bound to host {HOST} and port {PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    #print(f"\nListening for peers on {HOST}:{PORT}")
    while True:
        #print(f"\nEnters 'listen4peers' while loop")
        # accepting incoming connections from peers
        conn, addr = s.accept()
        # starting a new thread to handle the connection from the peer
        #print(f"\nStarting a new thread to handle connection from peerconn")
        threading.Thread(target=peerconn, args=(conn, addr)).start()
        

# fn to handle sending data to all connected peers
def senddata():
    #print(f"\nSENDDATA EXECUTING")
    global peers
    while True:
        #print(f"\nEntering sendData while loop")
        # get input
        message = input("Enter a message to send: ")
        # encrypting the message using the reverse cipher
        encrypted_message = message[::-1]
        # broadcasting the encrypted message to all connected peers
        for peer in peers:
            peer.send(encrypted_message.encode())
        


# fn to connect to a new peer
def connect2peer(peer_host, peer_port):
    global peers
    # prompting the user for the password
#    password = getpassword()
#    # checking if the password is correct - NOT DOING THIS ANYMORE CUZ ITS JUST PLAIN
#TEXT USING SHA 256 NOW 
#    if password == PASSWORD:
        # creating a new socket and connecting it to the specified peer
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_host, peer_port))
    #s.connect(('192.168.64.3', 9998)) #this should hep?
    # adding the new peer to the list of connected peers
    peers.append(s)
    print(f"\nConnected to peer: {peer_host}:{peer_port}")
    # new thread to handle sending data to all connected peers
    threading.Thread(target=senddata).start()
    while True:
        # receiving data from the peer
        data = s.recv(100)
        if not data:
            # remove the peer from the list of connected peers if no data is received
            peers.remove(s)
            print(f"Peer disconnected: {peer_host}:{peer_port}")
            break
        # decrypting the received data using the reverse cipher
        decrypted_data = data.decode()[::-1]
        # printing it
        if peer_port != PORT:
            print(f"\nReceived from {peer_host}:{peer_port}: {decrypted_data}")
        else:
            break
#    else:
#        print("Incorrect password, connection denied.")


# new thread to listen for incoming peers
#print(f"\nSTART LISTENING FOR INCOMING CONNECTIONS FROM PEERS IN NEW THREAD")
threading.Thread(target=listen4peers).start()
#time.sleep(100)
#threading.Thread(target=listen4peers).start()

#print(f"\nconnecting to some initial peers while loop and Y/N")
password = getpassword()
    # checking if the password is correct
if password!="89e01536ac207279409d4de1e5253e01f4a1769e696db0d6062ca9b8f56767c8":
    client_socket.send(b"Invalid password. Closing connection.")
    client_socket.close()
    #return
        
else:
    while True:
        #print("\nDo you wish to continue ? (reply with Y/N)")
        bool = input("Do you wish to continue ? (reply with Y/N)")
        if bool == "Y":
            #connect2peer('localhost', 9999)
            connect2peer('localhost', 9999)
            #connect2peer('localhost', 9997)
            #banana = banana + 1

            continue
        else:
            "OK "
            break
#else:
#    print("Incorrect password, connection denied.")

#    connect2peer('localhost', 9999)
#    connect2peer('localhost', 9998)
