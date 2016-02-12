import socket
import binascii

packet = binascii.unhexlify('b1ae01100001000000000000204644464a454f455046414644464a46444341434143414341434143414341424d0000200001')

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#s.sendto(packet, ('192.168.0.255', 137))
s.sendto(packet, ('127.0.0.1', 137))

