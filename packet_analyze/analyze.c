#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "checksum.h"
#include "analyze.h"
#include "print.h"

#ifndef ETHERTYPE_IP6
#define ETHERTYPE_IP6 0x86dd
#endif

int analyze_packet(u_char *data,int size){
	u_char *ptr;
	int lest;
	struct ether_header *eh;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct ether_header)){
		fprintf(stderr,"lest(%d)<sizeof(struct ether_header)\n",lest);
		return -1;
	}
	eh=(struct ether_header *)ptr;
	ptr+=sizeof(struct ether_header);
	lest-=sizeof(struct ether_header);

	switch(ntohs(eh->ether_type)){
		case ETHERTYPE_ARP:
			fprintf(stderr,"Packet[%dbytes]\n",size);
			print_ether_header(eh,stdout);
			analyze_arp(ptr,lest);
			break;
		case ETHERTYPE_IP:
			fprintf(stderr,"Packet[%dbytes]\n",size);
			print_ether_header(eh,stdout);
			analyze_ip(ptr,lest);
			break;
		case ETHERTYPE_IPV6:
			fprintf(stderr,"Packet[%dbytes]\n",size);
			print_ether_header(eh,stdout);
			analyze_ipv6(ptr,lest);
			break;
		default:;
	}
	return 0;
}

int analyze_arp(u_char *data,int size){
	u_char *ptr;
	int lest;
	struct ether_arp *arp;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct ether_arp)){
		fprintf(stderr,"lest(%d)<sizeof(struct ether_arp)\n",lest);
		return -1;
	}
	arp=(struct ether_arp *)ptr;
	ptr+=sizeof(struct ether_arp *);
	lest-=sizeof(struct ether_arp *);

	print_arp(arp,stdout);

	return 0;
}


int analyze_ip(u_char *data,int size){
	u_char *ptr;
	int lest;
	struct iphdr *iphdr;
	u_char *option;
	int option_len,len;
	unsigned short sum;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct iphdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct iphdr)\n",lest);
		return -1;
	}
	iphdr=(struct iphdr *)ptr;
	ptr+=sizeof(struct iphdr);
	lest-=sizeof(struct iphdr);
	
	//skip option contents
	option_len=iphdr->ihl*4 - sizeof(struct iphdr);
	if(option_len>0){
		if(option_len>=1500){
			fprintf(stderr,"IP optionLen(%d):too big\n",option_len);
			return -1;
		}
		option=ptr;
		ptr+=option_len;
		lest-=option_len;
	}
	//I remove because cheksum will be done  in analyze udp,tcp ,or icmp
	/*if(check_IPDATA_checksum(iphdr,option,option_len)==0){
		fprintf(stderr,"bad ip checksum\n");
		return -1;
	}*/
	print_ip_header(iphdr,option,option_len,stdout);
	
	switch(iphdr->protocol){
		case IPPROTO_ICMP:
			len=ntohs(iphdr->tot_len) - iphdr->ihl * 4;
			sum=checksum(ptr,len);
			if(sum!=0&&sum!=0xFFFF){
				fprintf(stderr,"bad icmp checksum\n");
				return -1;
			}
			analyze_icmp(ptr,lest);
			break;
		case IPPROTO_TCP:
			len=ntohs(iphdr->tot_len) - iphdr->ihl *4;
			if(check_IPDATA_checksum(iphdr,ptr,len)==0){
				fprintf(stderr,"bad tcp cheksum\n");
				return -1;
			}
			analyze_tcp(ptr,lest);
			break;
		case IPPROTO_UDP:
			{
				struct udphdr *udphdr;
				udphdr=(struct udphdr *)ptr;
				len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
				if(udphdr->check!=0&&check_IPDATA_checksum(iphdr,ptr,len)==0){
					fprintf(stderr,"bad udp checksum\n");
					return -1;
				}
				analyze_udp(ptr,lest);
			}
			break;
	}
	return 0;
}

int analyze_ipv6(u_char *data,int size){
	u_char *ptr;
	int lest;
	struct ip6_hdr *ip6;
	int len;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct ip6_hdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct ip6_hdr)\n",lest);
		return -1;
	}
	ip6=(struct ip6_hdr *)ptr;
	ptr+=sizeof(struct ip6_hdr);
	lest-=sizeof(struct ip6_hdr);

	print_ip6_header(ip6,stdout);
	
	switch(ip6->ip6_nxt){
		case IPPROTO_ICMPV6:
			len=ntohs(ip6->ip6_plen);
			if(check_IP6DATA_checksum(ip6,ptr,len)==0){
				fprintf(stderr,"bad icmp6 checksum\n");
				return -1;
			}
			analyze_icmp6(ptr,lest);
			break;
		case IPPROTO_TCP:
			len=ntohs(ip6->ip6_plen);
			if(check_IP6DATA_checksum(ip6,ptr,len)==0){
				fprintf(stderr,"bad tcp6 cheksum\n");
				return -1;
			}
			analyze_tcp(ptr,lest);
			break;
		case IPPROTO_UDP:
			len=ntohs(ip6->ip6_plen);
			if(check_IP6DATA_checksum(ip6,ptr,len)==0){
				fprintf(stderr,"bad udp6 checksum\n");
				return -1;
			}
			analyze_udp(ptr,lest);
			break;
	}
	return 0;
}

int analyze_icmp(u_char *data,int size){
	u_char *ptr;
	int lest;
	struct icmp *icmp;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct icmp)){
		fprintf(stderr,"lest(%d)<sizeof(struct icmp)\n",lest);
		return -1;
	}
	icmp=(struct icmp *)ptr;
	ptr+=sizeof(struct icmp);
	lest-=sizeof(struct icmp);
	print_icmp(icmp,stdout);

	return 0;
}

int analyze_icmp6(u_char *data,int size){
	u_char *ptr;
	int lest;
	struct icmp6_hdr *icmp6;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct icmp6_hdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct icmp6_hdr)\n",lest);
		return -1;
	}
	icmp6=(struct icmp6_hdr *)ptr;
	ptr+=sizeof(struct icmp6_hdr);
	lest-=sizeof(struct icmp6_hdr);
	print_icmp6(icmp6,stdout);

	return 0;
}

int analyze_tcp(u_char *data,int size){
	u_char *ptr;
	int lest;
	struct tcphdr *tcphdr;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct tcphdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct tcphdr)\n",lest);
		return -1;
	}
	tcphdr=(struct tcphdr *)ptr;
	ptr+=sizeof(struct tcphdr);
	lest-=sizeof(struct tcphdr);
	print_tcp(tcphdr,stdout);

	return 0;
}

int analyze_udp(u_char *data,int size){
	u_char *ptr;
	int lest;
	struct udphdr *udphdr;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct udphdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct udphdr)\n",lest);
		return -1;
	}
	udphdr=(struct udphdr *)ptr;
	ptr+=sizeof(struct udphdr);
	lest-=sizeof(struct udphdr);
	print_udp(udphdr,stdout);

	return 0;
}


