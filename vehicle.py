import socket
import secrets
import pickle
from tinyec import registry
from nacl.public import PrivateKey
import binascii
import struct
# Create a UDP socket


def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = ('localhost', 10027)


curve = registry.get_curve('brainpoolP256r1')
alicePrivKey = secrets.randbelow(curve.field.n)            #vehicle's private key
alicePubKey = alicePrivKey * curve.g                       #vehicle's public key
#privKey = PrivateKey.generate()
#pubKey = privKey.public_key

#print("privKey:", binascii.hexlify(bytes(privKey)))
#print("pubKey: ", binascii.hexlify(bytes(pubKey)))
print("privKey:", alicePrivKey)
print("pubKey: ", alicePubKey)
print("pubKey: ", alicePubKey.x)
print("type:",type(alicePubKey))
print("pubKey: ", hex(alicePubKey.x))
#message = binascii.hexlify(bytes(pubKey))
#messagex = bytes(str(alicePubKey.x),'utf-8')
#messagey = bytes(str(alicePubKey.y),'utf-8')
#message = bytes(str(alicePubKey),'utf-8')
message = pickle.dumps(alicePubKey)                        #public key 

num=123        #real id of vehicle


try:

    # Send data
    print('sending {!r}'.format(message))
    #sent = sock.sendto(messagex, server_address)
    #sent = sock.sendto(messagey, server_address)
    sent = sock.sendto(message, server_address)                  #sending vehicle's public key to TRA
    sent = sock.sendto(struct.pack("!i", num),server_address)    #sending vehicle's Real id to TRA
    data, address = sock.recvfrom(4096)
    #alicePubKey = (datax,datay)
    data=pickle.loads(data)                                      #receiving pseudo id of vehicle from TRA(but actually its just waiting to 																	receive )
    print('**********')
    print(data)
finally:
    print('closing socket')
    sock.close()
