from twisted.internet.protocol import DatagramProtocol
from twisted.internet import protocol, reactor, endpoints

import binascii
import struct
from samba import ndr
from samba.dcerpc import nbt
from samba.dcerpc import misc

import settings
from packets import *

def nullByteTrim(data):
    for i in range(len(data)):
        if ord(data[i]) == 0: return data[:i]
    return None
def wideNullByteTrim(data):
    for i in range(0, len(data), 2):
        if ord(data[i]) == 0 and ord(data[i+1]) == 0: return data[:i]
    return None
def Encode_Name(original_name, suffix):
    if (len(original_name) < 15):
        original_name += ''.join([' ' for i in range(15-len(original_name))])
    original_name += chr(suffix)

    return ''.join([chr((ord(c)>>4) + ord('A'))
                        + chr((ord(c)&0xF) + ord('A')) for c in original_name])

def Decode_Name(nbname):
        #From http://code.google.com/p/dpkt/ with author's permission.
        try:
                from string import printable

                if len(nbname) != 32:
                        return nbname

                l = []
                for i in range(0, 32, 2):
                        l.append(chr(((ord(nbname[i]) - 0x41) << 4) | ((ord(nbname[i+1]) - 0x41) & 0xf)))
                
                return (filter(lambda x: x in printable, ''.join(l).split('\x00', 1)[0].replace(' ', '')), ord(l[-1]))

        except:
                return "Illegal NetBIOS name"


def handleData(data):

    datagram_len = struct.unpack(">H", data[10:12])[0]
    print datagram_len
    sourceName = Decode_Name(data[15:47])
    destinationName = Decode_Name(data[49:81])
    print "Source: %s<%d>" % sourceName
    print "Destination: %s<%d>" % destinationName

    smb_header = data[82:]
    print smb_header[0:4] == '\xffSMB'
    smb_body = smb_header[32:]
    data_offset = struct.unpack("<H", smb_body[25:27])[0]
    transaction_name = nullByteTrim(smb_body[37:])
    print data_offset
    print transaction_name
    sam_logon = smb_body[37+len(transaction_name)+1:]
    computer_name = wideNullByteTrim(sam_logon[4:])
    username = wideNullByteTrim(sam_logon[4+len(computer_name)+2:])
    mailslot_name = nullByteTrim(sam_logon[4+len(computer_name)+2+len(username)+2:])

    class NetBiosDatagram(Packet):
        fields = OrderedDict([
            ("MessageType", "\x10"),
            ("Flags", "\x0e"),
            ("DatagramID", "\xc9\xb8"),
            ("SourceIP", "\xc0\xa8\x00\x01"), #192.168.0.1
            ("SourcePort", "\x00\x8a"), # 138
            ("Length", "\x00\x00"),
            ("PacketOffset", "\x00\x00"),
            ("SourceName", ""),
            ("DestinationName", ""),
            ("data", "")])
        def calculate(self):
            self.fields["Length"] = struct.pack(">H", len(str(self.fields["data"])) + 68) # Size from SourceName onwards, inclusive

    class SMBTransNetLogonReply(Packet):
            fields = OrderedDict([
                    ("Wordcount", "\x11"),
                    ("TotalParamCount", "\x00\x00"),
                    ("TotalDataCount","\x87\x00" ),
                    ("MaxParamCount", "\x00\x00"),
                    ("MaxDataCount","\xff\xff"),
                    ("MaxSetupCount", "\x00"),
                    ("Reserved1","\x00"),
                    ("Flags", "\x00\x00"),
                    ("Timeout","\x00\x00\x00\x00"),
                    ("Reserved2","\x00\x00"),
                    ("ParamCount","\x00\x00"),
                    ("ParamOffset", "\x00\x00"),
                    ("DataCount", "\x87\x00"),
                    ("DataOffset", "\x5c\x00"),
                    ("SetupCount", "\x03"),
                    ("Reserved3", "\x00"),
                    ("Mailslot Opcode", "\x01\x00"),
                    ("Mailslot Priority", "\x01\x00"),
                    ("Class", "\x02\x00"),
                    ("Bcc", "\x9e\x00"),
                    ("TransactionName", "\x00"),
                    ("data", "")])

            def calculate(self):
                    dataoffset = 0
                    for key in self.fields.keys():
                        if (key == 'data'): break
                        dataoffset += len(self.fields[key])

                    self.fields["TotalDataCount"] = struct.pack("<H", len(self.fields['data'])) #Size from ResponseCode onward, inclusive
                    self.fields["DataCount"] = struct.pack("<H", len(self.fields['data'])) #Same as TotalDataCount
                    self.fields["DataOffset"] = struct.pack("<H", dataoffset+32) #Size up to ResponseCode, non-inclusive, plus 32 (SMBHeader)

                    bcc = -1
                    for key in self.fields.keys():
                        if (key == 'Bcc'): bcc = 0
                        elif bcc >= 0: bcc += len(self.fields[key])

                    self.fields["Bcc"] = struct.pack("<H", bcc) #Size from BCC onward, noninclusive

    x = nbt.NETLOGON_SAM_LOGON_RESPONSE_EX()
    x.command = 0x17
    x.sbz = 0
    x.server_type = 0x000003fd
    x.domain_uuid = misc.GUID("6cb2d967-f2b7-4c93-bce1-d943eda330a1")
    x.forest = destinationName[0].lower()
    x.dns_domain = destinationName[0].lower()
    x.pdc_dns_name = "debian-smb." + destinationName[0].lower()
    x.domain_name = destinationName[0]
    x.pdc_name = "DEBIAN-SMB"
    #x.user_name = ""
    x.server_site = "Default-First-Site-Name"
    x.client_site = "Default-First-Site-Name"
    x.sockaddr_size = 8 # FIXME: Should be 16
    x.sockaddr.sockaddr_family = 2
    x.sockaddr.pdc_ip = '192.168.0.1'
    # FIXME: This padding doesn't encode properly with the samba library
    #x.sockaddr.remaining = '\x00\x00\x00\x00\x00\x00\x00\x00'
    x.nt_version = 13
    x.lmnt_token = 0xffff
    x.lm20_token = 0xffff
    y = ndr.ndr_pack(x)

    #Hacky fix for the above FIXME
    print binascii.hexlify(y)
    y = y[:-18] + '\x10\x02\x00\x00\x00\xc0\xa8\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00' + '\x0d\x00\x00\x00\xff\xff\xff\xff'
    print binascii.hexlify(y)

    Header = SMBHeader(cmd="\x25", mid="\x00\x00")
    Body = SMBTransNetLogonReply(
      TransactionName=mailslot_name + '\x00',
      data = str(y))
    Body.calculate()

    nb = NetBiosDatagram(SourceName='\x20' + Encode_Name(destinationName[0], destinationName[1]) + '\x00',
      DestinationName='\x20' + Encode_Name(sourceName[0], sourceName[1]) + '\x00',
      data=str(Header) + str(Body))
    nb.calculate()

    return str(nb)

class NetLogonUDP(DatagramProtocol):
    def datagramReceived(self, datagram, address):
        print "Received from address: " + str(address)
        self.transport.write(handleData(datagram), address)
        print "Finished sending reply."

if __name__ == "__main__":
    reactor.listenUDP(138, NetlogonUDP())
    reactor.run()

