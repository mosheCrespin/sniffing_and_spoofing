#include <pcap/pcap.h>
#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include <unistd.h>//for close()
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h> //ethernet header
#include<netinet/ip.h>	//ip header
#include <pthread.h>//for sleep()

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};




//////////////////////

void send_raw_ip_packet(struct iphdr* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);//create raw socket
    if(sock<0){
    	perror("[-] root privileges required ");
    	exit(1);
    	}

    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable))==-1)//socket option
      {
      	perror("setsockopt");
        exit(1);
        }
                     
    //destinat	ion info
    dest_info.sin_family = AF_INET;//ip v4
    dest_info.sin_addr.s_addr = ip->daddr;
    //send the packet
    if(sendto(sock, ip, ntohs(ip->tot_len), 0, 
           (struct sockaddr *)&dest_info, sizeof(dest_info))==-1)
           {
           perror("sendto");
             exit(1);
           }
    printf("[+] spoofed ICMP echo reply sent\n");       
    close(sock);
    sleep(1);
}
//////////////////////////////



void spoof_icmp_reply(const u_char *packet){

   char buffer[1500];
   memset(buffer, 0, 1500);
   
    //fill ip header
   struct iphdr *old_ip = (struct iphdr*)(packet + sizeof(struct ether_header)); 
   struct iphdr *new_ip = (struct iphdr*) buffer;
   
   char *data=(u_char *) packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmpheader);
   int size_of_data=htons(old_ip->tot_len)-(sizeof(struct iphdr) + sizeof(struct icmpheader));
   memcpy((buffer+sizeof(struct iphdr) + sizeof(struct icmpheader)), data, size_of_data);

   new_ip->version = old_ip->version;
   new_ip->ihl = old_ip->ihl;
   new_ip->ttl = 44;
   new_ip->saddr = old_ip->daddr;
   new_ip->daddr = old_ip->saddr;//spoofed dest
   new_ip->protocol = IPPROTO_ICMP; 
   new_ip->tot_len = htons(sizeof(struct iphdr) + 
                       sizeof(struct icmpheader) + size_of_data);
      
   //fill icmp header
   struct icmpheader *new_icmp = (struct icmpheader *) 
                             (buffer + sizeof(struct iphdr));
   struct icmpheader *old_icmp = (struct icmpheader *) 
                             (packet + sizeof(struct ether_header) + sizeof(struct iphdr));                          
   new_icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.
   new_icmp->icmp_id=old_icmp->icmp_id;
   new_icmp->icmp_seq=old_icmp->icmp_seq;
   // Calculate the checksum for integrity
   new_icmp->icmp_chksum = 0;//init
   new_icmp->icmp_chksum = in_cksum((unsigned short *)new_icmp, sizeof(struct icmpheader)+ size_of_data);
   
   
   
   //send the packet
   send_raw_ip_packet (new_ip);

}

////////////////////////////////

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    printf("got a new ICMP packet:\n");
    struct ether_header *eth =(struct ether_header *) packet;
    if(htons(eth-> ether_type) == 0x800){ //check if it's ip type
    	struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ether_header));//ip header
    	struct icmpheader *icmp = (struct icmpheader *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));          
        if(icmp->icmp_type!=8)//check if it is an echo request
            return;
        spoof_icmp_reply(packet);  
        }
                                 

}

int main(){
    pcap_t *handle;//handle the interface
    char errbuf[PCAP_ERRBUF_SIZE];//buffer for errors
    struct bpf_program fp;//compiled filter program
    char filter_exp[]="ip proto ICMP";
    bpf_u_int32 net;//ip
    handle= pcap_open_live("enp0s3" , 8192,1,1000,errbuf);//(interface , length(maximum bytes to cupture),promiscuos mode ,time out,errbuf)
    if(pcap_compile(handle,&fp, filter_exp,0, net)==-1)//compile into fp with icmp
    {
    	pcap_perror(handle, "Error:");//could not parse the exp
        exit(1);
    }
    if(pcap_setfilter(handle,&fp)==-1){//set the filter to be icmp
        pcap_perror(handle, "Error:");
        exit(1);
    }
    pcap_loop(handle, -1, got_packet, NULL);//enter to a loop, for every pokcet send for proccssing to got_pocket

    pcap_close(handle);//close handle
    
    return 0;
}



