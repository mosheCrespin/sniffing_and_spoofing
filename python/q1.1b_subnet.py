from scapy.all import *

def print_pkt(pkt):
    pkt.show()
print('[+]sniffinf packets from 128.120.0.0/16 or to 128.120.0.0/16...')
pkt=sniff(filter= 'dst net 128.120.0.0/16 or src net 128.120.0.0/16', prn=print_pkt)


