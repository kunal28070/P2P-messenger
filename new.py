import socket
import threading
import hashlib
import random as r
import time as t

from collections import defaultdict

# DHT-related classes and functions
class DHT:
    def __init__(self):
        self.storage = {}
        for i in range(256):
            self.storage[i] = []

    def add_node(self, node_id, addr):
        if node_id not in self.storage:
            self.storage[node_id] = []
        self.storage[node_id].append(addr)

    def get_node(self, node_id):
        return self.storage.get(node_id, [])

    def remove_node(self, node_id, addr):
        if node_id in self.storage:
            self.storage[node_id].remove(addr)
            if not self.storage[node_id]:
                del self.storage[node_id]

    def hash_function(self, data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def get_connected_nodes(self, node_id):
        connected_nodes = []
        for key in self.storage:
            if node_id in self.storage[key]:
                connected_nodes.extend(self.storage[key])
        return connected_nodes

# Create a DHT instance
dht = DHT()
temp = 0 
array_hospital = {}
# The remaining code is not changed
peers = []
PASSWORD = 'mypassword'
port = None
class Hospital:
    def __init__(self, bed_stock = 100, syringes_stock = 1000, MRI_machines_stock = 30, patient_total_capacity = 500, patient_count = 250, last_received_message = '', ip = '127.0.0.1', port = 0):
        self.bed_stock = bed_stock
        self.syringes_stock = syringes_stock
        self.MRI_machines_stock = MRI_machines_stock
        self.patient_total_capacity = patient_total_capacity
        self.patient_count = patient_count
        self._update_patient_extra_spaces() # To update the extra space every time previous two values are changed
        self.last_received_message = last_received_message #Store a last received message
        self.ip = ip
        self.port = port
        
    def network_connect(self):
        self.ip = str(input("Please enter the ip address:"))
        self.port = int(input("Please enter the port:"))
        
    def _update_patient_extra_spaces(self): # To update the extra space every time previous two values are changed
        self.patient_extra_spaces = self.patient_total_capacity - self.patient_count
        
    def show_attributes(self): # To show all attributes of the class (used in 'edit')
        attributes = vars(self)
        for attribute in attributes:
            if attribute != 'last_received_message':
                if attribute != 'ip':
                    if attribute != 'port':
                        print(attribute,getattr(self, attribute))

    
    def info_all(self): #Info about all attributes and their values (used in 'info')
        attributes = [
            ("Bed stock", self.bed_stock),
            ("Syringes stock", self.syringes_stock),
            ("MRI machines stock", self.MRI_machines_stock),
            ("Patient total capacity", self.patient_total_capacity),
            ("Patient count", self.patient_count),
            ("Patient extra spaces", self.patient_extra_spaces),
            ("Last received message", self.last_received_message),
            ("IP Address", self.ip),
            ("PORT number", self.port),
        ]
        for attr_name, attr_value in attributes:
            #print(f"{attr_name}: {attr_value}") #3.11
            print("%s: %s" % (attr_name, attr_value)) #2.7
        print("\n")
        
# TESTING VARIOUS HOSPITALS. REMOVE FOR DEMO
            
me = Hospital() #Declaring myself as Hospital

StJames = Hospital() #StJames
Mater = Hospital() #Mater
#Change various attribute values for Mater
Mater.bed_stock = 56
Mater.syringes_stock = 0
Mater.MRI_machines_stock = 0
Mater.patient_total_capacity = 250
Mater.patient_count = 150
Mater._update_patient_extra_spaces()
parts = {}
hospitals = ["me", "StJames", "Mater"] #A list of connected Hospitals
# SYNTAX CHECKING FUNCTIONS

def does_exist(class_name): #To check if Hospital with given name exists 
    global parts
    class_name = parts[1]
    
    if class_name in globals():
        return 1
    else:
        #print(f"{class_name} Hospital does not exist.") #3.11
        print("%s Hospital does not exist." % class_name) #2.7
        return 0
    
def does_exist2(class_name): #Same as before, but used in a different command
    global parts
    class_name = parts[3]
    
    if class_name in globals():
        #print(f"{class_name} exists!")
        return 1
    else:
        #print(f"{class_name} Hospital does not exist.") #3.11
        print("%s Hospital does not exist." % class_name) #2.7
        return 0
    
def is_object(me, object_name): #Check if the attribute exists in Hospital
    global parts
    object_name = parts[1]
    if hasattr(me, object_name):
        return 1
    else:
        #print(f"{object_name} does not exist in Hospitals") #3.11
        print("%s does not exist in Hospitals." % object_name) #2.7
        return 0

# DEFINING FUNCTIONS

def send_message(target, message): #Send message and change the 'last_received_message' of receiver to it
    if(does_exist(target)):
        #print(f"Sending message to {target} : '{message}'") #3.11
        print("Sending message to %s: '%s'" % (target, message)) #2.7
        message = message + " / from me" # needs to be changed to whoever sent it
        setattr(eval(target), 'last_received_message', message)

def edit_node(object_name, object_count): #Edit the attribute values (Say ten syringes got lost)
    if is_object(me, object_name):
        setattr(me, object_name, object_count)

def send_items(target, item_type, item_count): #Send 'gifts' to other Hospitals, if have extra stuff
    if is_object(me, item_type) and does_exist2(target):
        #print(f"Sending {item_count} of '{item_type}' from {target}") #3.11
        print("Sending %d of '%s' from %s" % (item_count, item_type, target)) #2.7
        if request_response(): #Check if the hospital accepts the offer
        # increase count in me, decrease in target
            #print(f"{target} accepted the gift!") #3.11
            print("%s accepted the gift!" % target) #2.7
            
            #print(f"Sending {item_count} of {item_type}. Please type 'info me' to check the changes") #3.11
            print("Sending %d of %s. Please type 'info me' to check the changes" % (item_count, item_type)) #2.7
            current = getattr(me, item_type)
            new_value = current - item_count #Decrement the number for 'me'
            setattr(me, item_type, new_value)
            
            current_target = getattr(eval(target), item_type)
            new_value_target = current_target + item_count #Increment for 'target'
            setattr(eval(target), item_type, new_value_target)
        else: #If did not accept the offer, say it did not
            #print(f"{target} did not accept the gift.") #3.11
            print("%s did not accept the gift." % target) #2.7

def request(target, item_type, item_count): #Works very much like 'send' but + and - are changed places
    if is_object(me, item_type) and does_exist2(target):
        #print(f"Requesting {item_count} of '{item_type}' from {target}") #3.11
        print("Requesting {} of '{}' from {}".format(item_count, item_type, target)) #2.7

        if request_response():
        # increase count in me, decrease in target
            print("Request accepted!")
            #print(f"Receiving {item_count} of {item_type}. Please type 'info me' to check the changes") #3.11
            print("Receiving {} of {}. Please type 'info me' to check the changes".format(item_count, item_type)) #2.7
            current = getattr(me, item_type)
            new_value = current + item_count
            setattr(me, item_type, new_value)
            
            current_target = getattr(eval(target), item_type)
            new_value_target = current_target - item_count
            setattr(eval(target), item_type, new_value_target)
        else:
            print("Response declined.")
    
def info(class_name): #Check the attributes of a Hospital if it exists
    if does_exist(class_name):
        globals()[class_name].info_all()
        
def request_response(): #Returns 'yes' or 'no' with a 50/50 chance (to accept sends or requests)
    t.sleep(r.randint(3, 7)) #this is here to emulate the human response delay. Remove when added to main code
    return (r.randint(0, 10))

def who_exists(): #Output connected Hospitals
    for i in hospitals:
        print(i)

def broadcast(message):
    for peer in peers:
        try:
            peer.sendall(message.encode("utf-8"))
        except Exception as e:
            print("Error broadcasting message: %s" % e)

def request(target, item_type, item_count):
    if is_object(me, item_type) and does_exist2(target):
        print("Requesting {} of '{}' from {}".format(item_count, item_type, target))

        if request_response():
            print("Request accepted!")
            print("Receiving {} of {}. Please type 'info me' to check the changes".format(item_count, item_type))
            current = getattr(me, item_type)
            new_value = current + item_count
            setattr(me, item_type, new_value)

            current_target = getattr(eval(target), item_type)
            new_value_target = current_target - item_count
            setattr(eval(target), item_type, new_value_target)

            # Broadcast the request to all connected nodes
            broadcast("REQUESTED {} {} {}".format(target, item_type, item_count))
        else:
            print("Response declined.")

def commands():
    global parts
    for i in range(20):
        print("\n")
    print("---------------------------------------------------------------------------------------------------")
    print("Welcome to the network!\n")

    me.network_connect()

    print("To get started with commands, enter 'help' or '<command> help' to get help with a specific command\n")

    while True: #Forever loop which can be broken by 'exit'
        user_input = input("Enter a command: ")
        parts = user_input.split()

        if (len(parts) < 2 and len(parts) != 1):#If command has almost no words
            print("Invalid command: not enough arguments") #Doesnt work
            continue
        elif user_input == 'exit': #Terminate the program if 'exit'. Equivalent to leaving the network
            print("Exiting the program. Goodbye.")
            break
        elif user_input == 'help': #if entered 'help', give info about all available commands and connected peers
            print("Currently available commands:")
            print("msg <receiver> <message>")
            print("edit <object> <number>")
            print("send <object> <number> <receiver>")
            print("request <object> <number> <target>")
            print("info <target>")
            print("")
            print("Here are the connected Hospitals:")
            who_exists()
            print("\n")
            continue
        elif user_input == 'msg' or user_input == 'msg help': #To help sending message
            print("The correct syntax is: msg <receiver> <message>") # shows correct syntax
            print("\n")
            continue
        elif user_input == 'edit' or user_input == 'edit help':
            print("The correct syntax is: edit <object> <number>")
            print("\n")
            print("Objects able to be edited:") # shows available attributes
            me.show_attributes()
            print("\n")
            continue
        elif user_input == 'send' or user_input == 'send help':
            print("The correct syntax is: send <object> <number> <receiver>")
            print("\n")
            continue
        elif user_input == 'request' or user_input == 'request help':
            print("The correct syntax is: request <object> <number> <target>")
            print("\n")
            continue
        elif user_input == 'info' or user_input == 'info help':
            print("The correct syntax is: info <target>")
            print("\n")
            continue
        elif len(parts) == 1 :
            print("Invalid command: not enough arguments")
            print("\n")
            continue

        #Define what part of input is what
        
        command = parts[0] 
        target = parts[1]
        object = parts[1]
        
        class_name = ''

        if command == "msg": #Messaging command
            if len(parts) < 3: #These lines are here to check if the correct syntax is used
                print("Invalid command, the correct syntax is: msg <receiver> <message>")
                continue
            message = ' '.join(parts[2:])
            send_message(target, message)
        elif command == "edit":
            if len(parts) < 3:
                print("Invalid command, the correct syntax is: edit <object> <number>")
                continue
            object_name = parts[1]
            object_count = int(parts[2])
            edit_node(object_name, object_count)
            #print(f"Trying to set {object_name} to {object_count}. Please type 'info me' to check the changes") #3.11
            print("Trying to set {} to {}. Please type 'info me' to check the changes".format(object_name, object_count)) #2.7

        elif command == "send":
            if len(parts) < 4:
                print("Invalid command, the correct syntax is: send <object> <number> <receiver>")
                continue
            item_type = parts[1]
            item_count = int(parts[2])
            target = parts[3]
            send_items(target, item_type, item_count)
        elif command == "request":
            if len(parts) < 4:
                print("Invalid command, the correct syntax is: request <object> <number> <Hospital>")
                continue
            item_type = parts[1]
            item_count = int(parts[2])
            target = parts[3]
            request(target, item_type, item_count)
        elif command == "info":
            if len(parts) < 2:
                print("Invalid command, the correct syntax is: info <target>")
                continue
            class_name = parts[1]
            #does_exist(class_name)
            info(class_name)
            
        elif command == "exit": #again if exit break
            break
        
        else: #If some gibberish is entered
            print("Unknown command")

def getpassword():
    abc = input("Please enter password: ")
    hashed_password = hashlib.sha256(abc.encode('utf-8')).hexdigest()
    return hashed_password

def peerConn(conn, addr):
    global peers
    global dht
    node_id = dht.hash_function(str(addr))
    dht.add_node(node_id, addr)

    peers.append(conn)
    print("\nNew peer connected: %s" % str(addr))
    if peers:
        commands()
        # temp = temp +1 

    while True:
        data = conn.recv(1024)
        if not data:
            peers.remove(conn)
            print("Peer disconnected: %s" % str(addr))
            connected_nodes = dht.get_connected_nodes(node_id)
            for connected_node in connected_nodes:
                dht.remove_node(node_id, connected_node)
            break

        # Handle incoming requests for beds and update the respective hospital's bed stock
        message = data.decode("utf-8")
        # if message.startswith("REQUESTED"):
        #     _, target, item_type, item_count = message.split()
        #     item_count = int(item_count)
        #     target = str(target)

        #     if does_exist2(target) and is_object(me, item_type):
        #         if target == 'Mater':
        #             Mater.bed_stock = Mater.bed_stock - item_count
        #         if target == 'StJames':
        #             StJames.bed_stock = StJames.bed_stock - item_count
                # current_target = getattr(eval(target), item_type)
                # new_value_target = current_target - item_count
                # setattr(eval(target), item_type, new_value_target)
                # print("Updated beds for {}: {} -> {}".format(target, current_target, new_value_target))

def listen4peers():
    global dht
    global port
    global peers
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = input("\nEnter the port number : ")
    HOST = input("\n Enter the IP address : ")
    s.bind((HOST, int(port)))
    s.listen(3)
    print("\nNode added %s:%s" % (HOST, port))

    while True:
        conn, addr = s.accept()
        threading.Thread(target=peerConn, args=(conn, addr)).start()

def sendData():
    global peers
    global dht
    global temp
    commands()
    # exec(open('messaging.py').read())
    while True:
        # temp = temp + 1; 
        message = input("Enter a message to send: ")
        encrypted_message = message[::-1]

        for peer in peers:
            peer.send(encrypted_message.encode())

def connect2peer(peer_host, peer_port):
    global port
    global peers
    global dht
    global temp 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((peer_host, peer_port))
    except ConnectionRefusedError:
        print ("\nConnection to %s:%s refused." % (peer_host, peer_port))
        return

    node_id = dht.hash_function("%s %s"%(peer_host,peer_port))
    dht.add_node(node_id, (peer_host, peer_port))
    peers.append(s)
    print("\nConnected to peer: %s %s"%(peer_host,peer_port))
    threading.Thread(target=sendData).start()

    while True:
        try:
            data = s.recv(100)
            if not data:
                # Remove the disconnected peer from the list of peers
                peers.remove(s)
                # Get the list of connected nodes to the disconnected peer
                connected_nodes = dht.get_connected_nodes(node_id)
                # Remove the disconnected peer from the DHT
                dht.remove_node(node_id, (peer_host, peer_port))
                # Connect the remaining peers to each other
                for connected_node in connected_nodes:
                    connected_node_id = dht.hash_function(str(connected_node))
                    connected_node_host, connected_node_port = connected_node
                    # Connect the neighbors of the disconnected peer to each other
                    for neighbor_node in dht.get_connected_nodes(connected_node_id):
                        neighbor_node_id = dht.hash_function(str(neighbor_node))
                        neighbor_node_host, neighbor_node_port = neighbor_node
                        if (neighbor_node_host, neighbor_node_port) != (peer_host, peer_port):
                            # Only connect the nodes that are not the disconnected peer or itself
                            threading.Thread(target=connect2peer, args=(neighbor_node_host, neighbor_node_port)).start()

                print ("\nPeer disconnected: %s %s"%(peer_host,peer_port))
                break

            decrypted_data = data.decode()
            if peer_port != int(port):
                print("\nReceived from %s %s : %s"%(peer_host,peer_port,decrypted_data))
                if decrypted_data.startswith("REQUESTED"):
                    print("\nfuck yeah\n")
                    _, target, item_type, item_count = decrypted_data.split()
                    item_count = int(item_count)
                    target = str(target)

                    # if does_exist2(target) and is_object(me, item_type):
                    if target == 'Mater':
                        Mater.bed_stock = Mater.bed_stock - item_count
                    if target == 'StJames':
                        StJames.bed_stock = StJames.bed_stock - item_count
            else:
                break
        except ConnectionResetError:
            peers.remove(s)
            print("Peer disconnected: %s %s"%(peer_host,peer_port))
            connected_nodes = dht.get_connected_nodes(node_id)
            for connected_node in connected_nodes:
                connected_node_id = dht.hash_function(str(connected_node))
                dht.remove_node(connected_node_id, (peer_host, peer_port))
                # Share the list of connections with the neighbor
                dht.add_node(connected_node_id, connected_node, neighbor=(peer_host, peer_port))
            break
if __name__ == '__main__':

    threading.Thread(target=listen4peers).start()

    password = getpassword()
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if password != "89e01536ac207279409d4de1e5253e01f4a1769e696db0d6062ca9b8f56767c8":
        client_socket.send(b"Invalid password. Closing connection.")
        client_socket.close()
    else:
        while True:
            bool = input("Do you wish to continue ? (reply with Y/N)")
            if bool == "Y":
                if temp == 0 :
                    new_IP = input("\n Enter the IP address of the peer to be connected :")
                    new_Port = input("\n Enter the port number of the peer to be connected :")
                    connect2peer(new_IP, int(new_Port))
                    continue
            else:
                print("OK")
                break