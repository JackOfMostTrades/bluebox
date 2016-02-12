
import sys
sys.path.append('./ldaptor')

import binascii
from ldaptor import ldapfilter
from ldaptor.protocols import pureber, pureldap
from ldaptor.protocols.ldap import ldaperrors
from samba import ndr
from samba.dcerpc import nbt
from samba.dcerpc import misc
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import protocol, reactor, endpoints

berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
    inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(
            fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(
            fallback=pureber.BERDecoderContext())))

def findDomain(filt):
    if isinstance(filt, pureldap.LDAPFilter_and):
        for x in filt:
            d = findDomain(x)
            if d != None: return d
    if isinstance(filt, pureldap.LDAPFilter_equalityMatch):
        if (filt.attributeDesc.value == 'DnsDomain'):
            return filt.assertionValue.value
    return None

lastDomain = None

def buildReply(data):
    global lastDomain

    msg, bytes = pureber.berDecodeObject(berdecoder, data)
    msgId = msg.id
    print msgId
    msg = msg.value
    assert isinstance(msg, pureldap.LDAPProtocolRequest)
    print msg.__class__.__name__
    print msg.baseObject
    print msg.scope
    domain = findDomain(msg.filter)
    if (domain.endswith('.')): domain = domain[0:-1]
    print "Received search for domain: %s" % domain
    lastDomain = domain.split('.')

    x = nbt.NETLOGON_SAM_LOGON_RESPONSE_EX()
    x.command = 23
    x.sbz = 0
    x.server_type = 0x000003fd
    x.domain_uuid = misc.GUID("6cb2d967-f2b7-4c93-bce1-d943eda330a1")
    x.forest = '.'.join(lastDomain)
    x.dns_domain = '.'.join(lastDomain)
    x.pdc_dns_name = "debian-smb." + '.'.join(lastDomain)
    x.domain_name = lastDomain[0].upper()
    x.pdc_name = "DEBIAN-SMB"
    #x.user_name = ""
    x.server_site = "Default-First-Site-Name"
    x.client_site = "Default-First-Site-Name"
    x.sockaddr_size = 0
    x.sockaddr.pdc_ip = '0.0.0.0'
    x.nt_version = 5
    x.lmnt_token = 0xffff
    x.lm20_token = 0xffff

    #print ndr.ndr_print(x)
    y = ndr.ndr_pack(x)
    attrs = [('netlogon', [ str(y) ])]

    print binascii.hexlify(str(y))
    result = ''
    result += str(pureldap.LDAPMessage(pureldap.LDAPSearchResultEntry(
		    objectName='',
	  	    attributes=attrs),
                id=msgId))
    result += str(pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(
		    resultCode=ldaperrors.Success.resultCode),
                id=msgId))

    return result

def buildSecondReply(data):
    global lastDomain

    msg, bytes = pureber.berDecodeObject(berdecoder, data)
    msgId = msg.id
    print msgId
    msg = msg.value
    assert isinstance(msg, pureldap.LDAPProtocolRequest)
    print msg.__class__.__name__
    print msg.baseObject
    print msg.scope

    dc = ["DC=" + x for x in lastDomain]
    dc = ','.join(dc)

    attrs = []
    attrs.append(('configurationNamingContext', ['CN=Configuration,' + dc]))
    attrs.append(('defaultNamingContext', [dc]))
    attrs.append(('rootDomainNamingContext', [dc]))
    attrs.append(('schemaNamingContext', ['CN=Schema,CN=Configuration,' + dc]))
    attrs.append(('subschemaSubentry', ['CN=Aggregate,CN=Schema,CN=Configuration,' + dc]))
    attrs.append(('supportedCapabilities', [
        '1.2.840.113556.1.4.800',
        '1.2.840.113556.1.4.1670',
        '1.2.840.113556.1.4.1791',
        '1.2.840.113556.1.4.1935',
        '1.2.840.113556.1.4.2080'
    ]))
    attrs.append(('supportedLDAPVersion', ['2', '3']))
    attrs.append(('dsServiceName', ['CN=NTDS Settings,CN=DEBIAN-SMB,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,' + dc]))
    attrs.append(('serverName', ['CN=DEBIAN-SMB,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,' + dc]))
    attrs.append(('dnsHostName', ['debian-smb.' + '.'.join(lastDomain)]))
    attrs.append(('ldapServiceName', ['.'.join(lastDomain) + ':debian-smb$@' + '.'.join(lastDomain).upper()]))
    attrs.append(('supportedControl', [
        '1.2.840.113556.1.4.841',
        '1.2.840.113556.1.4.319',
        '1.2.840.113556.1.4.473',
        '1.2.840.113556.1.4.1504',
        '1.2.840.113556.1.4.801',
        '1.2.840.113556.1.4.801',
        '1.2.840.113556.1.4.805',
        '1.2.840.113556.1.4.1338',
        '1.2.840.113556.1.4.529',
        '1.2.840.113556.1.4.417',
        '1.2.840.113556.1.4.2064',
        '1.2.840.113556.1.4.1413',
        '1.2.840.113556.1.4.1413',
        '1.2.840.113556.1.4.1413',
        '1.2.840.113556.1.4.1413',
        '1.2.840.113556.1.4.1413',
        '1.2.840.113556.1.4.1339',
        '1.2.840.113556.1.4.1340',
        '1.2.840.113556.1.4.1413',
        '1.2.840.113556.1.4.1341'
    ]))
    attrs.append(('namingContexts', [
        dc,
        'CN=Configuration,' + dc,
        'CN=Schema,CN=Configuration,' + dc,
        'DC=DomainDnsZones,' + dc,
        'DC=ForestDnsZones,' + dc
    ]))
    attrs.append(('supportedSASLMechanisms', ['GSS-SPNEGO', 'GSSAPI', 'NTLM']))

    result = ''
    result += str(pureldap.LDAPMessage(pureldap.LDAPSearchResultEntry(
                    objectName='',
                    attributes=attrs),
                id=msgId))
    result += str(pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(
                    resultCode=ldaperrors.Success.resultCode),
                id=msgId))

    return result


class LdapUDP(DatagramProtocol):
    def datagramReceived(self, datagram, address):
        print "Received from address: " + str(address)
        self.transport.write(buildReply(datagram), address)
        print "Finished sending reply."

reactor.listenUDP(389, LdapUDP())

class LdapTCP(protocol.Protocol):
    def dataReceived(self, data):
        print "Received TCP."
        self.transport.write(buildSecondReply(data))
        print "Finished TCP reply."

class LdapTCPFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return LdapTCP()

endpoints.serverFromString(reactor, "tcp:389").listen(LdapTCPFactory())

reactor.run()

