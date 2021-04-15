#!/usr/bin/env python3

import socket
from struct import pack, unpack, unpack_from
from hashlib import sha256

HOST="ve3lsr.ca"
PORT=14519
PASS=""

LONG_CALLSIGN_LENGTH = 8

class ircddbRemote:

    def __init__(self, host, port, password):
        self.bufferSize = 1024
        self.host = host
        self.port = port
        self.password = password
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def logout(self):
        MESSAGE = b"LOG"
        self.sock.sendto(MESSAGE, (self.host, self.port))

    def login(self):
        MESSAGE = b"LIN"
        self.sock.sendto(MESSAGE, (self.host, self.port))
        msgFromServer = self.sock.recvfrom(self.bufferSize)

        if unpack("3s", msgFromServer[0][0:3])[0] != b"RND":
            print("ERROR")
            return "Error"

        rnd = unpack_from("I", msgFromServer[0], 3)[0]
        SHATEXT = pack(f"I{len(self.password)}s", rnd, self.password.encode())
        SHA=sha256(SHATEXT).digest()
        MESSAGE = pack('3s32s', b'SHA', SHA)
        self.sock.sendto(MESSAGE, (self.host, self.port))

        msgFromServer = self.sock.recvfrom(self.bufferSize)
        if unpack("3s", msgFromServer[0][0:3])[0] != b"ACK":
            print("ERROR")
            return "Error"

    def getCallSigns(self):
        MESSAGE = b"GCS"
        self.sock.sendto(MESSAGE, (self.host, self.port))
        msgFromServer = self.sock.recvfrom(self.bufferSize)
        if unpack("3s", msgFromServer[0][0:3])[0] != b"CAL":
            print("ERROR")
            return "Error"
        list = []
        total = int((len(msgFromServer[0])-3)/(LONG_CALLSIGN_LENGTH+1))
        for count in range( total ):
            list.append( unpack_from(f"c{LONG_CALLSIGN_LENGTH}s", msgFromServer[0], ((LONG_CALLSIGN_LENGTH+1)*count)+3) )

        return list

    def getRepeater(self, repeater):
        MESSAGE = pack(f"3s{len(repeater)}s", b"GRP", repeater)
        self.sock.sendto(MESSAGE, (self.host, self.port))
        msgFromServer = self.sock.recvfrom(self.bufferSize)

        if unpack("3s", msgFromServer[0][0:3])[0] != b"RPT":
            print("ERROR")
            return "Error"

        print( unpack_from(f"{LONG_CALLSIGN_LENGTH}sI{LONG_CALLSIGN_LENGTH}s", msgFromServer[0], 3) )
        # New offset 23
        total = int((len(msgFromServer[0])-23)/24)
        list = []
        for count in range( total ):
            list.append( unpack_from(f"{LONG_CALLSIGN_LENGTH}sIIII", msgFromServer[0], ((24)*count)+23) )

        print(list)
#        msg = "Message from Server {}".format(msgFromServer[0])
#        print(msg)

    def link(self, repeater, reflector, reconnect=0):
        MESSAGE = pack(f"!3s{LONG_CALLSIGN_LENGTH}sI{LONG_CALLSIGN_LENGTH}s", b"LNK", repeater, reconnect, reflector)
        self.sock.sendto(MESSAGE, (self.host, self.port))

    def unlink(self, repeater, reconnect=0):
        MESSAGE = pack(f"!3s{LONG_CALLSIGN_LENGTH}sI{LONG_CALLSIGN_LENGTH}s", b"LNK", repeater, reconnect, b"")
        self.sock.sendto(MESSAGE, (self.host, self.port))


t = ircddbRemote(HOST, PORT, PASS)
t.login()
print ( t.getCallSigns() )
t.getRepeater(b"VE3LSR C")
t.getRepeater(b"VE3LSR B")
# t.link(b"VE3LSR B", b"XLX104 B")
t.link(b"VE3LSR B", b"XRF103 B")
#t.unlink(b"VE3LSR B")
t.logout()
