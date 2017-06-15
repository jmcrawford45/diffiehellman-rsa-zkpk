'''
    Simple socket server using threads
'''
 
import socket
import sys
from thread import *
from dh import DH
import random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import base64



secret_match = 123456
secret_other = 123123
possible_secrets = [secret_match, secret_other]

#Load key
bobPrivKey = RSA.importKey(open('bob.priv').read())
signer = PKCS1_v1_5.new(bobPrivKey)

alicePubKey = RSA.importKey(open('alice.pub').read())
verifier = PKCS1_v1_5.new(alicePubKey)

def signAndSend(conn, msg):
    signature = signer.sign(SHA256.new(msg))
    conn.sendall(msg + ',' + base64.b64encode(signature))

def verifyMsg(data):
    elements = data.split(',')[:-1]
    msg = ','.join(elements)
    if not verifier.verify(SHA256.new(msg), base64.b64decode(data.split(',')[-1])):
        print('Protocol failure! Bad RSA signature!')
        sys.exit()
 
HOST = ''   # Symbolic name meaning all available interfaces
PORT = 4321 # Arbitrary non-privileged port
exchange = DH()
PRIME = exchange.getPrime()
GENERATOR = exchange.getGen()
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print 'Socket created'
 
#Bind socket to local host and port
try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
     
print 'Socket bind complete'

#Start listening on socket
s.listen(10)
print 'Socket now listening'

#Function for handling connections. This will be used to create threads
def clientthread(conn):
    #Sending message to connected client
     
    #infinite loop so that function do not terminate and thread do not end.
    b = exchange.getRandomElement()
    b2 = exchange.getRandomElement()
    d = exchange.getRandomElement()
    m1 = str(exchange.getPublic(b))
    m2 = str(exchange.getPublic(b2))
    sb = random.choice(possible_secrets)
    print "BOB'S SECRET: %d\n---------------\n" % (sb)
    while True:
         
        #Step 2 respond
        data = conn.recv(1024)
        print 'received ' + data
        verifyMsg(data)
        data = ','.join(data.split(',')[:-1])
        if not data: 
            break
        k = int(exchange.getShared(b, int(data)))
        print 'secret: %d' % (k)
        print 'Step 2 send: %s' % (m1)
        signAndSend(conn, m1)
        #conn.sendall(m1)


        #Step 3 respond
        data = conn.recv(1024)
        print 'received ' + data
        verifyMsg(data)
        data = ','.join(data.split(',')[:-1])
        if not data: 
            break
        k2 = int(exchange.getShared(b2, int(data)))
        print 'secret: %d' % (k2)
        print 'Step 3 send: %s' % (m2)
        signAndSend(conn, m2)
        #conn.sendall(m2)

        #Step 4 receive, step 5 respond
        data = conn.recv(1024)
        print 'received ' + data
        verifyMsg(data)
        data = ','.join(data.split(',')[:-1])
        if not data or len(data.split(',')) != 2: 
            break
        kc = data.split(',')[0]
        kd = (k ** d) % PRIME
        challengeA = int(data.split(',')[1])
        print 'k2: %d, sb: %d, d: %d' % (k2,sb,d)
        challengeB = ((k2 ** sb) * (GENERATOR ** d)) % PRIME
        challengeBInv = (challengeB ** (PRIME - 2)) % PRIME
        print 'Step 5 send: %d' % (challengeBInv)
        m5 = str(int(challengeBInv))
        signAndSend(conn, m5)
        #conn.sendall(m5)

        #Step 6 receive, step 7 respond
        data = conn.recv(1024)
        print 'received ' + data
        verifyMsg(data)
        data = ','.join(data.split(',')[:-1])
        kdInv = (kd ** (PRIME - 2)) % PRIME
        k3Partial = (((challengeA * challengeBInv) % PRIME) ** b) % PRIME
        m7 = str(k3Partial) + ',' + str(int(kdInv))
        print 'Step 7: %s' % (m7)
        signAndSend(conn, m7)
        #conn.sendall(m7)
        k3 = int(exchange.getShared(b, int(data)))
        print 'secret: %d' % (k3)

        break

    conn.close()

    #came out of loop
 
#now keep talking with the client
while 1:
    #wait to accept a connection - blocking call
    conn, addr = s.accept()
    print 'Connected with ' + addr[0] + ':' + str(addr[1])
     
    #start new thread takes 1st argument as a function name to be run, second is the tuple of arguments to the function.
    start_new_thread(clientthread ,(conn,))
 
s.close()
