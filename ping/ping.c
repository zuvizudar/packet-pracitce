#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

unsigned short checksum(unsigned short *buf, int bufsz);
void analyze_recv(struct iphdr *iphdrptr,struct icmphdr *icmphdrptr);


int main(int argc,char *argv[]){
	int soc;
	struct icmphdr hdr;
	struct sockaddr_in addr;
	int tmp;
	u_char buf[2048];
	struct icmphdr *icmphdrptr;
	struct iphdr *iphdrptr;
	if(argc<=1){
		fprintf(stderr,"please host-name");
		return -1;
	}
	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr=inet_addr(argv[1]);

	//make raw_socket
	if((soc=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0){
		perror("socket error");
		return -1;
	}
	memset(&hdr,0,sizeof(hdr));

	//make ICMP_header
	hdr.type=ICMP_ECHO;
	hdr.code=0;
	hdr.checksum=0;
	hdr.un.echo.id=0;
	hdr.un.echo.sequence=0;

	hdr.checksum=checksum((unsigned short *)&hdr,sizeof(hdr));
	
	//sendto
	if((tmp=sendto(soc,(char *)&hdr,sizeof(hdr),0,(struct sockaddr *)&addr,sizeof(addr)))<1){
		perror("sendto error");
	}
	//recv
	if((tmp=recv(soc,buf,sizeof(buf),0))<1){
		perror("recv error");
	}
	iphdrptr=(struct iphdr *)buf;
	icmphdrptr=(struct icmphdr *)(buf + iphdrptr->ihl *4 );
	analyze_recv(iphdrptr,icmphdrptr);
	if(icmphdrptr->type==ICMP_ECHOREPLY){
		printf("OK");
	}
	else{
		printf("received ICMP %d\n",icmphdrptr->type);
	}
	close(soc);
	return 0;
}

void analyze_recv(struct iphdr *iphdrptr,struct icmphdr *icmphdrptr){
	struct in_addr *saddr=NULL;
	struct in_addr *daddr=NULL;
	char ip_str[18]={};

	printf("ihl   %d\n", iphdrptr->ihl);
	printf("ver   %d\n", iphdrptr->version);
	printf("tos   %d\n", iphdrptr->tos);
	printf("len   %d\n", ntohs(iphdrptr->tot_len));
	printf("id    %d\n", ntohs(iphdrptr->id));
	printf("frag  %d\n", iphdrptr->frag_off);
	printf("ttl   %d\n", iphdrptr->ttl);
	printf("proto %d\n", iphdrptr->protocol);
	printf("check %d\n", iphdrptr->check);

	//printf("saddr %d\n", iphdrptr->saddr);
	//printf("daddr %d\n", iphdrptr->daddr);
	printf("src ip:");
	saddr=(struct in_addr*)&(iphdrptr->saddr);
	inet_ntop(AF_INET,saddr,&ip_str[0],(socklen_t)sizeof(ip_str));
	printf("%s\n",ip_str);
	memset(&ip_str[0],0x00,sizeof(ip_str));
	printf("dst ip:");
	daddr=(struct in_addr*)&(iphdrptr->daddr);
	inet_ntop(AF_INET,daddr,&ip_str[0],(socklen_t)sizeof(ip_str));
	printf("%s\n",ip_str);


	printf("type  %d\n", icmphdrptr->type);
	printf("code  %d\n", icmphdrptr->code);
	printf("check %d\n", icmphdrptr->checksum);
	printf("id    %d\n", icmphdrptr->un.echo.id);
	printf("seq   %d\n", icmphdrptr->un.echo.sequence);

}
 
unsigned short checksum(unsigned short *buf, int bufsz){
  unsigned long sum = 0;

  while (bufsz > 1) {
    sum += *buf;
    buf++;
    bufsz -= 2;
  }

  if (bufsz == 1) {
    sum += *(unsigned char *)buf;
  }

  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}


