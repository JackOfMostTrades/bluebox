# -*- coding: utf-8 -*-

"""
    FixedResolver - example resolver which responds with fixed response
                    to all requests
"""

from __future__ import print_function

import copy
import sys
sys.path.append('./dnslib');

from dnslib import RR
from dnslib.dns import QTYPE, SRV
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

class FixedResolver(BaseResolver):
    """
        Respond with fixed response to all requests
    """
    def __init__(self,zone):
        # Parse RRs
        self.rrs = RR.fromZone(zone)

    def resolve(self,request,handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]

        if qtype == 'SRV':
            port = 389
            if qname.label[0] == '_kpasswd':
                port = 464
            a = RR.fromZone('. 60 IN SRV 0 100 %d 192.168.0.1' % port)[0]
            a.rname = qname
            reply.add_answer(a)
        else:
            # Replace labels with request label
            for rr in self.rrs:
                a = copy.copy(rr)
                a.rname = qname
                reply.add_answer(a)
        return reply

if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="Fixed DNS Resolver")
    p.add_argument("--response","-r",default=". 60 IN A 192.168.0.1",
                    metavar="<response>",
                    help="DNS response (zone format) (default: 127.0.0.1)")
    p.add_argument("--zonefile","-f",
                    metavar="<zonefile>",
                    help="DNS response (zone file, '-' for stdin)")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Server port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Listen address (default:all)")
    p.add_argument("--udplen","-u",type=int,default=0,
                    metavar="<udplen>",
                    help="Max UDP packet length (default:0)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP server (default: UDP only)")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action='store_true',default=False,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()
    
    if args.zonefile:
        if args.zonefile == '-':
            args.response = sys.stdin
        else:
            args.response = open(args.zonefile)

    resolver = FixedResolver(args.response)
    logger = DNSLogger(args.log,args.log_prefix)

    print("Starting Fixed Resolver (%s:%d) [%s]" % (
                        args.address or "*",
                        args.port,
                        "UDP/TCP" if args.tcp else "UDP"))

    for rr in resolver.rrs:
        print("    | ",rr.toZone().strip(),sep="")
    print()

    if args.udplen:
        DNSHandler.udplen = args.udplen

    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

