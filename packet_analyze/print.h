char *my_ether_ntoa_r(u_char *hwaddr,char *buf,socklen_t size);
char *arp_ip2str(u_int8_t *ip,char *buf,socklen_t size);
char *ip_ip2str(u_int32_t ip,char *buf,socklen_t size);
int print_ether_header(struct ether_header *eh,FILE *fp);
int print_arp(struct ether_arp *arp,FILE *fp);
int print_ip_header(struct iphdr *iphdr,u_char *option,int optionlen, FILE *fp);
int print_ip6_header(struct ip6_hdr *ip6,FILE *fp);
int print_icmp(struct icmp *icmp,FILE *fp);
int print_icmp6(struct icmp6_hdr *icmp6,FILE *fp);
int print_tcp(struct tcphdr *tcphdr,FILE *fp);
int print_udp(struct udphdr *udphdr,FILE *fp);

