from scapy.all import *
ip=IP(src="8.8.8.8",dst="192.168.56.6")
icmp=ICMP()
pkt=ip/icmp
send(pkt)
