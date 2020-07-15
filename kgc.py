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

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('localhost', 10028)


curve = registry.get_curve('brainpoolP256r1')
alicePrivKey = secrets.randbelow(curve.field.n)                  #private key of kgc
alicePubKey = alicePrivKey * curve.g                             #public key of kgc
#privKey = PrivateKey.generate()
#pubKey = privKey.public_key
#print("privKey:", binascii.hexlify(bytes(privKey)))
#print("pubKey: ", binascii.hexlify(bytes(pubKey)))
print("privKey:", alicePrivKey)
print("pubKey: ", alicePubKey)




try:

    data, address = sock.recvfrom(4096)                         #receiving the pseudo id of a vehicle(not receiving anything as of now)
    #alicePubKey = (datax,datay)
    data=pickle.loads(data)
    print('****************')
    print(data)
finally:
    print('closing socket')
    sock.close()
