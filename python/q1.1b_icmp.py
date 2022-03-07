from scapy.all import *
print("[+]sniffing icmp..")
def print_pkt(pkt):
    pkt.show()      
    
pkt=sniff(filter= 'icmp' , prn=print_pkt)
