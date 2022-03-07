from scapy.all import *
host="google.com"
i=1
counter=0
while True:
    #build the packet
    ip=IP(dst=host, ttl=i)
    icmp=ICMP()
    pkt=ip/icmp
    reply=sr1(pkt, verbose=0, timeout=3)
    #if timeout then we will get None
    if reply is None:
        print("{} - Request timed out.".format(i))
    elif reply.type == 0:#waiting for echo reply

        print ("dest addr: {0} is in length of: {1}".format(reply.src,counter))
        break	
    else:
        print("{0} - curr addr: {1}".format(i,reply.src))
        counter+=1
    i+=1
    #we stop the loop after 30 times
    if i==31:
    	print("the specified addr is unreachable")
    	break
    
