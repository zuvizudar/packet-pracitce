u_int16_t checksum(u_char *data,int len);
u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2) ;
int check_ip_checksum(struct iphdr *iphdr,u_char *option,int optionLen);
int check_IPDATA_checksum(struct iphdr *iphdr,unsigned char *data,int len);
int check_IP6DATA_checksum(struct ip6_hdr *ip,unsigned char *data,int len);
