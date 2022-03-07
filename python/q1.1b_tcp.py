from scapy.all import *
def print_pkt(pkt):
    pkt.show()
print('[+]sniffinf TCP packets from 192.168.56.102 who sent to port 23...')     
pkt=sniff(filter= 'tcp and dst port 23 and src host 192.168.56.4 ' , prn=print_pkt)

