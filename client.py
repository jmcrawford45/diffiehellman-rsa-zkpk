import socket   #for sockets
import sys  #for exit
from dh import DH
import random
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64



secret = 123456
print "ALICE'S SECRET: %d\n---------------\n" % (secret)

#Load key
alicePrivKey = RSA.importKey(open('alice.priv').read())
signer = PKCS1_v1_5.new(alicePrivKey)

bobPubKey = RSA.importKey(open('bob.pub').read())
verifier = PKCS1_v1_5.new(bobPubKey)


def signAndSend(conn, msg):
    signature = signer.sign(SHA256.new(msg))
    conn.sendall(msg + ',' + base64.b64encode(signature))

def verifyMsg(data):
    elements = data.split(',')[:-1]
    msg = ','.join(elements)
    if not verifier.verify(SHA256.new(msg), base64.b64decode(data.split(',')[-1])):
        print('Protocol failure! Bad RSA signature!')
        sys.exit()

 
def getResponse(isInt = True):
    data = None
    while True:
        #Receiving from server
        data = s.recv(1024)
        print 'received ' + data
        verifyMsg(data)
        data = ','.join(data.split(',')[:-1])
        if data: 
            break
    if not isInt: return data
    return int(str(data))

def getShared(secret):
    message = str(exchange.getPublic(secret))
    try :
        #Send the whole string
        signAndSend(s, message)
        #s.sendall(message)
    except socket.error:
        #Send failed
        print 'Send failed in DH secret derivation!'
        sys.exit()
    k = int(exchange.getShared(secret, getResponse()))
    print 'secret: %d' % (k)
    return k
     
try:
    #create an AF_INET, STREAM socket (TCP)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error, msg:
    print 'Failed to create socket. Error code: ' + str(msg[0]) + ' , Error message : ' + msg[1]
    sys.exit();
 
print 'Socket Created'
 
host = 'localhost'
port = 4321
 
try:
    remote_ip = socket.gethostbyname( host )
 
except socket.gaierror:
    #could not resolve
    print 'Hostname could not be resolved. Exiting'
    sys.exit()
     
print 'Ip address of ' + host + ' is ' + remote_ip
 
#Connect to remote server
s.connect((remote_ip , port))
 
print 'Socket Connected to ' + host + ' on ip ' + remote_ip
 
#Send some data to remote server
exchange = DH()
PRIME = exchange.getPrime()
GENERATOR = exchange.getGen()

#Step 2 of the protocol
a = exchange.getRandomElement()
k = getShared(a)

#Step 3 of the protocol
a2 = exchange.getRandomElement()
k2 = getShared(a2)

#Step 4 of the protocol
c = exchange.getRandomElement()
kc = (k ** c) % PRIME
challenge = (k2 ** secret * GENERATOR ** c) % PRIME
try:
    #Set the whole string
    m4 = str(kc) + ',' + str(challenge)
    print 'Step 4 send: %s' % (m4)
    signAndSend(s, m4)
    #s.sendall(m4)
except socket.error:
    #Send failed
    print 'Send failed in step 4'
    sys.exit()

#Step 5
challengeB = getResponse()

#Step 6
k3Partial = (((challenge * challengeB) % PRIME) ** a) % PRIME
try :
    #Set the whole string
    print 'Step 6 send: %d' % (k3Partial)
    signAndSend(s, str(k3Partial))
    #s.sendall(str(k3Partial))
except socket.error:
    #Send failed
    print 'Send failed in step 6'
    sys.exit()

#Step 7
res = getResponse(False)
if not res or len(res.split(',')) != 2:
    print 'Server disobeyed protocol by not sending two values in step 7!' 
    sys.exit()
kdInv = int(res.split(',')[1])
k3 = (int(res.split(',')[0]) ** a) % PRIME
print 'secret: %d' % (k3)

#Verification
if (kdInv * kc) % PRIME == k3:
    print 'Secrets match!'
else:  
    print 'Secrets do not match!'
 
print 'Protocol ended successfully'