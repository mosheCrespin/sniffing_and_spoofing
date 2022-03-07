#include <unistd.h>
#include <pcap/pcap.h>
#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h> //ethernet header
#include<netinet/ip.h>	//ip header
#include<netinet/tcp.h> //tcp header
#include<ctype.h>//for isprint()



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    printf("\ngot a new packet:\n");
    struct ether_header *eth =(struct ether_header *) packet;
    if(htons(eth-> ether_type) == 0x800){ //check if it's ip type
    	struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ether_header));//ip header
    	struct sockaddr_in source,dest;//for src and dest of the meassege
    	memset(&source, 0, sizeof(source));
    	source.sin_addr.s_addr = ip->saddr;//for the src ip
    	memset(&dest, 0, sizeof(dest));
    	dest.sin_addr.s_addr = ip->daddr;//for the dest ip
    	printf("Source IP: %s" ,inet_ntoa(source.sin_addr));
    	printf(" Destination IP: %s\n" ,inet_ntoa(dest.sin_addr));
    	char *data=(u_char *) packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    	int size_of_data=htons(ip->tot_len)-(sizeof(struct iphdr) + sizeof(struct tcphdr));
    	if(size_of_data>0)
    	{
    	    data+=size_of_data-1;
    	    if(isprint(*data))
    	        printf("->%c\n", *data);
    	        }
}
}

int main(){
    pcap_t *handle;//handle the interface
    char errbuf[PCAP_ERRBUF_SIZE];//buffer for errors
    struct bpf_program fp;//compiled filter program
    char filter_exp[] = "proto TCP and (dst portrange 10-100)";
    bpf_u_int32 net;
    handle= pcap_open_live("enp0s3" , 8192,1,1000,errbuf);//(interface , length(maximum bytes to cupture),promiscuos mode ,time out,errbuf)
    if(handle==NULL)
    {
    	pcap_perror(handle, "Error:");
        exit(1);
    }
    if(pcap_compile(handle,&fp, filter_exp,0, net)!=0)//compile into fp with icmp
    {
    	pcap_perror(handle, "Error:");//could not parse the exp
        exit(1);

    }
    if(pcap_setfilter(handle,&fp)!=0){//set the filter to be icmp
        pcap_perror(handle, "Error:");
        exit(1);
    }
    pcap_loop(handle, -1, got_packet, NULL);//enter to a loop, for every pokcet send for proccssing to got_pocket

    pcap_close(handle);//close handle
    
    return 0;

}

