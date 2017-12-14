int analyze_packet(u_char *data,int size);
int analyze_arp(u_char *data,int size);
int analyze_ip(u_char *data,int size);
int analyze_ipv6(u_char *data,int size);
int analyze_icmp(u_char *data,int size);
int analyze_icmp6(u_char *data,int size);
int analyze_tcp(u_char *data,int size);
int analyze_udp(u_char *data,int size);
