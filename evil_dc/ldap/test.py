
import binascii
from ldaptor import ldapfilter
from ldaptor.protocols import pureber, pureldap
from ldaptor.protocols.ldap import ldaperrors
from samba import ndr
from samba.dcerpc import nbt
from samba.dcerpc import misc

packet = binascii.unhexlify('3084000001040201016384000000fb04000a01000a0100020100020100010100a084000000d4a3840000001c0409446e73446f6d61696e040f6d69736b61746f6e69632e756e692ea384000000170404486f7374040f4445534b544f502d44514c4d473337a384000000250409446f6d61696e5369640418010400000000000515000000b9e81cc93f161323478e6dbca3840000001e040a446f6d61696e4775696404109833dc516c2789468b2bcf581b826058a3840000000d04054e74566572040416000000a3840000002d040b446e73486f73744e616d65041e4445534b544f502d44514c4d4733372e6d69736b61746f6e69632e756e6930840000000a04084e65746c6f676f6e')

berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
    inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(
            fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(
            fallback=pureber.BERDecoderContext())))

msg, bytes = pureber.berDecodeObject(berdecoder, packet)
msgId = msg.id
print msgId
msg = msg.value
assert isinstance(msg, pureldap.LDAPProtocolRequest)
print msg.__class__.__name__
print msg.baseObject
print msg.scope

def findDomain(filt):
    if isinstance(filt, pureldap.LDAPFilter_and):
        for x in filt:
            d = findDomain(x)
            if d != None: return d
    if isinstance(filt, pureldap.LDAPFilter_equalityMatch):
        if (filt.attributeDesc.value == 'DnsDomain'):
            return filt.assertionValue.value
    return None

domain = findDomain(msg.filter)

x = nbt.NETLOGON_SAM_LOGON_RESPONSE_EX()
x.command = 23
x.sbz = 0
x.server_type = 0x000003fd
x.domain_uuid = misc.GUID("6cb2d967-f2b7-4c93-bce1-d943eda330a1")
x.forest = 'miskatonic.uni'
x.dns_domain = 'miskatonic.uni'
x.pdc_dns_name = "debian-smb.miskatonic.uni"
x.domain_name = "MISKATONIC"
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
            attributes=attrs)))
result += str(pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(
                resultCode=ldaperrors.Success.resultCode),
                id=msgId))

print binascii.hexlify(result)

