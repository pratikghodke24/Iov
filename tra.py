import socket
import struct
import secrets 
import pickle
import tinyec.ec as ec
import hashlib, binascii
from tinyec import registry
from nacl.public import PrivateKey
import binascii
import time
# Create a UDP socket

def xor_two_str(a,b):
    return ''.join([hex(ord(a[i%len(a)]) ^ ord(b[i%(len(b))]))[2:] for i in range(max(len(a), len(b)))])


def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            #socket for vehicle
sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)           #socket for kgc

# Bind the socket to the port
server_address = ('localhost', 10027)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)
server_address1 = ('localhost', 10028)
print('starting up on {} port {}'.format(*server_address1))
sock1.bind(server_address1)

curve = registry.get_curve('brainpoolP256r1')
bobPrivKey = secrets.randbelow(curve.field.n)                          #private key of TRA
bobPubKey = bobPrivKey * curve.g                                       #public key of TRA
#privKey = PrivateKey.generate()
#pubKey = privKey.public_key

#print("privKey:", binascii.hexlify(bytes(privKey)))
#print("pubKey: ", binascii.hexlify(bytes(pubKey)))
print("privKey:", bobPrivKey)             
print("pubKey: ", compress(bobPubKey))


try:
    print('\nwaiting to receive message')
    #datax, address = sock.recvfrom(4096)
    #datay, address = sock.recvfrom(4096)
    data, address = sock.recvfrom(4096)                               #receiving public key of vehicle
    #alicePubKey = (datax,datay)
    data=pickle.loads(data)
    obj1=bobPrivKey * data                          
    print(obj1)
    print("type:",data)
    data1, address = sock.recvfrom(4096)                              #receiving real id of vehicle
    num = struct.unpack('!i',data1)
    int1 = num[0]
    #print('received {} bytes from {}'.format(
     #   len(data), address))
    print(data)
    print('received {} bytes from {}'.format(
        len(num), address))
    print(int1)
    ts = time.time()
    print(ts)
    obj1=str(obj1)
    bobPubKey = str(bobPubKey)
    ts = str(ts)
    temp = obj1+ts+bobPubKey
    num= str(num)
    sha256hash = hashlib.sha256(temp.encode('utf-8')).digest()
   
    print("SHA-256('temp') = ", binascii.hexlify(sha256hash))
    sha256hash= str(sha256hash)
    obj3 = xor_two_str(num,sha256hash)                                 #pseudo id of vehilce
    print(obj3)
    pid = pickle.dumps(obj3)
    sent = sock.sendto(pid, server_address)                            #sending pseudo id to vehilce(error)
    print("pid sent")
    pid1 = pickle.dumps(obj3)
    sent1 = sock1.sendto(pid1, server_address1)                        #sending pseudo id to kgc(error)
    print("pid sent")
finally:
    print('closing socket')
    sock.close()
