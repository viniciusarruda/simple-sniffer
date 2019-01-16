#include <arpa/inet.h>   /* To use inet_ntoa() */
#include <ctype.h>       /* This header declares a set of functions to classify and transform individual characters. (isprint) */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>       /* To use signal() */
#include <string.h>
#include <unistd.h>       /* To use sleep() */

#include <net/ethernet.h>     /* Provides declarations for ethernet header */  
#include <netinet/ip.h>       /* Provides declarations for ip header       */
#include <netinet/ip_icmp.h>  /* Provides declarations for icmp header     */
#include <netinet/igmp.h>     /* Provides declarations for igmp header     */
#include <netinet/tcp.h>      /* Provides declarations for tcp header      */
#include <netinet/udp.h>      /* Provides declarations for udp header      */


#define MAXNUMBYTES2CAPTURE 65535 /* 65536 (2^16) (0 - 65535)  Size of package (In bytes) that will be saved on package */

#define	ETH_TYPE_IP 2048	    /* Same as ETHERTYPE_IP 0x0800, but in decimal. (IP protocol) */
#define	ETH_TYPE_ARP 2054	    /* Same as ETHERTYPE_ARP 0x0806, but in decimal. (Address resolution) */

#define UNDEFINED "ETHE/UND"
#define LLC       "ETHE/LLC"
#define ETHERNET  "ETHERNET"
#define WIRELESS  "WIRELESS"
#define IP        "   IP   "
#define ARP       "  ARP   "
#define ICMP      "IP/ICMP "
#define TCP       "  TCP   "
#define UDP       "  UDP   "
#define IGMP      "IP/IGMP "
#define UNKNOWN   " ------ "
#define OTHER     " OTHER  "
#define NONE      "  NONE  "

#define TEMPFILE_N "temporary.tmp"


/* ARP Header, (assuming Ethernet+IPv4)            */ 
struct arpheader 
{ 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}; 


void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet); 
void signal_callback(int signum);

void ethernet_handler(const u_char* packet, unsigned int caplen);
void ip_handler(const u_char* packet, unsigned int caplen);
void arp_handler(const u_char* packet, unsigned int caplen);
void icmp_handler(const u_char* packet, unsigned int iph_size, unsigned int caplen);
void igmp_handler(const u_char* packet, unsigned int iph_size);
void tcp_handler(const u_char* packet, unsigned int iph_size, unsigned int caplen);
void udp_handler(const u_char* packet, unsigned int iph_size, unsigned int caplen);

void print_data(const u_char* data, unsigned int length);

int menu(char* device_n, int* mode, int* snaplen, char* pcap_file_n, char* logfile_n, char* raw_logfile_n);
void clean_screen(FILE* stream);
int open_files(const char* logfile_n, const char* raw_logfile_n, const char* mode);
int print_header_info(const char* device_n);
int open_pcapfile(const char* pcap_file_n, pcap_t* handler);
int end_menu(const char* logfile_n, const char* raw_logfile_n);
int merge_file(char* merged_file_n, const char* logfile_n, const char* raw_logfile_n);
void close_files(void);
int clean_file(const char* file_n);
int clean_rawfile(const char* rawfile_n);

void read_str(char *str, int len);
void clean_enter(FILE* stream);

FILE* logfile = NULL;              /* Good practice */
FILE* raw_logfile = NULL;          /* Good practice */
unsigned int aux;                  /* To help sums around the code */
long int init_time;                /* Stores the initial time. */
pcap_t* handler = NULL;            /* Good practice */
pcap_dumper_t* file_dumper = NULL; /* To use with pcap_dump, receive a pointer from pcap_dump_open */
struct in_addr addr;               /* To use with inet_ntoa() */ 
char errbuf[PCAP_ERRBUF_SIZE];     /* To receive errors from pcap functions */

/* Packet Information */
struct 
{
	unsigned int p_number;
	char p_time[9];
	char p_link[9];           /* Ethernet, Wireless, Other */
	char p_internet[9];       /* Ip, Arp, Icmp, Igmp, Other */
	char p_transport[9];      /* Tcp, Udp, Other */
} p_info;



int main(void) /* depois colocar os args para aceitar --help para ajuda e --about para sobre cool */
{
	int datalink_value, snaplen, mode; 
	struct timeval init; /* To use gettimeofday, to get the initial time. */
	char device_n[100], pcap_file_n[32], logfile_n[32], raw_logfile_n[32];  /* underline name  */
	
	p_info.p_number = 0; 
	
	/* Gets the initial time */
	gettimeofday(&init, NULL);
	init_time = init.tv_sec;
	
	
	while(!menu(device_n, &mode, &snaplen, pcap_file_n, logfile_n, raw_logfile_n));
	clean_screen(stdout);

    
    if(open_files(logfile_n, raw_logfile_n, "w"))
    	exit(EXIT_FAILURE);
    	
    if(print_header_info(device_n))
		exit(EXIT_FAILURE);


	/* open live capture */
	if((handler = pcap_open_live(device_n, snaplen, mode, 1000, errbuf)) == NULL)
	{
		clean_screen(stderr);
		fprintf(stderr, "\n\nError: %s.\n\n", errbuf);	
		sleep(2);
		exit(EXIT_FAILURE);
	}
	
	
	/* Register signal and signal handler */
	if(signal(SIGTSTP, signal_callback) == SIG_ERR)  /* SIGTSTP for ctrl + z and SIGINT for ctrl + c*/
	{
		clean_screen(stderr);
		fprintf(stderr, "\n\nError using signal function.\n\n");
		sleep(2);
		exit(EXIT_FAILURE);
	}
	
	/* Open pcap file */
	if(open_pcapfile(pcap_file_n, handler))
		exit(EXIT_FAILURE);
	
	/* Validates the datalink value (Because callback receives just an unsigned char (0 - 255)) */
	if((datalink_value = pcap_datalink(handler)) > 255) 
	{
		datalink_value = 255;  /* Its a flag (avoiding conversion error) !!! NOT BLUETOOTH (bluetooth it is represented by 255 code) */	
	}
	
	/* Loop forever */
	if(pcap_loop(handler, -1, callback, (u_char*) &datalink_value) == -1)
	{
		clean_screen(stderr);
		fprintf(stderr, "\n\nError. Something went wrong while looping.\n\n");
		sleep(2);
		exit(EXIT_FAILURE);
	}
	
	if(end_menu(logfile_n, raw_logfile_n))
		exit(EXIT_FAILURE);
	
	return 0;
}


/*Every time that a packet is captured by net card, the callback function will be called !*/
void 
callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{
	long int elapsed;
	
	pcap_dump((u_char*)file_dumper, h, packet); 
	
	p_info.p_number++; 
	
	fprintf(logfile , "%c***************************[Packet #%06d]****************************\n", 7, p_info.p_number);
	fprintf(raw_logfile , "%c", 7);
	
	elapsed = h->ts.tv_sec - init_time;
	sprintf(p_info.p_time, "%02ld:%02ld:%02ld", elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60);
	
	
	if(*user == DLT_EN10MB)  
	{
		ethernet_handler(packet, h->caplen); 
	}
	else
	{
		strcpy(p_info.p_link, OTHER);
		strcpy(p_info.p_internet, UNKNOWN);
		strcpy(p_info.p_transport, UNKNOWN);
		fprintf(logfile , "\nOther link protocol: #%d\n", *user);  /* http://www.tcpdump.org/linktypes.html (list of linktypes) */
		fprintf(raw_logfile, "Data Payload:\n   ");
		print_data(packet, h->caplen);
	}
	
	fprintf(logfile , "\n\n");
	fprintf(raw_logfile , "\n\n");
	printf("| #%06d | %s | %06d |  %06d  | %s | %s | %s  |\n", p_info.p_number, p_info.p_time, h->len, h->caplen, p_info.p_link, p_info.p_internet, p_info.p_transport);
}


void ethernet_handler(const u_char *packet, unsigned int caplen)
{
	struct ethhdr *eth = (struct ethhdr *) packet; 
	unsigned short protocol = ntohs(eth->h_proto); 
    
    fprintf(logfile , "\nEthernet Header\n"); 
    fprintf(logfile , "   |-MAC Destination Address : %02X-%02X-%02X-%02X-%02X-%02X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-MAC Source Address      : %02X-%02X-%02X-%02X-%02X-%02X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	
	fprintf(raw_logfile, "Ethernet Header:\n   ");
	print_data((const u_char*) eth, sizeof(struct ethhdr));
	
	/*
	*In order to allow some frames using Ethernet v2 framing and some using the original version of 802.3 framing to be used on the same Ethernet segment, EtherType values
	*must be greater than or equal to 1536 (0x0600). That value was chosen because the maximum length of the payload field of an Ethernet 802.3 frame is 1500 octets 
	*(0x05DC). Thus if the field's value is greater than or equal to 1536, the frame must be an Ethernet v2 frame, with that field being a type field.[10] If it's less 
	*than or equal to 1500, it must be an IEEE 802.3 frame, with that field being a length field. Values between 1500 and 1536, exclusive, are undefined.[11] This 
	*convention allows software to determine whether a frame is an Ethernet II frame or an IEEE 802.3 frame, allowing the coexistence of both standards on the same 
	*physical medium.	(font: Wikipedia)
	*/
	
	if(protocol >= 1536)
	{
		fprintf(logfile , "   |-Protocol                : 0x%04X \n", protocol);   
		strcpy(p_info.p_link, ETHERNET);
		switch(protocol) 
		{
			case ETH_TYPE_IP:
				ip_handler(packet, caplen);
				break;
			
			case ETH_TYPE_ARP:  
				strcpy(p_info.p_internet, ARP); 
				strcpy(p_info.p_transport, NONE);
				arp_handler(packet, caplen);
				break;
			
			default:
				strcpy(p_info.p_internet, OTHER);
				strcpy(p_info.p_transport, UNKNOWN); 
				fprintf(logfile , "\nOther network protocol : #0x%04X\n", protocol);				
			
				if(caplen > sizeof(struct ethhdr))
				{
					fprintf(raw_logfile, "\nData Payload:\n   ");
					print_data((const u_char*) eth + sizeof(struct ethhdr), caplen - (unsigned int) sizeof(struct ethhdr));
				}		  							  						  
		}
	}
	else
	{	
		if(protocol <= 1500)
		{                          
			strcpy(p_info.p_link, LLC); 
			fprintf(logfile , "   |-Length                  : %d\n", protocol);   
			fprintf(logfile , "\nLogical Link Control [IEEE 802.2 Frame]\n");		
		}
		else
		{
			strcpy(p_info.p_link, UNDEFINED); 
			fprintf(logfile , "   |-Length/Ethertype        : %d\n", protocol); 
			fprintf(logfile , "\n[Undefined by IEEE (IEEE Std 802.3-2005, 3.2.6)]\n");				
		}			            
		
		strcpy(p_info.p_internet, UNKNOWN);
		strcpy(p_info.p_transport, UNKNOWN); 		
	
		if(caplen > sizeof(struct ethhdr))
		{
			fprintf(raw_logfile, "\nData Payload:\n   ");
			print_data((const u_char*) eth + sizeof(struct ethhdr), caplen - (unsigned int) sizeof(struct ethhdr));
		}
	}
	
}


void ip_handler(const u_char *packet, unsigned int caplen)
{
	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
	
    fprintf(logfile , "\nIP Header\n");
    fprintf(logfile , "   |-IP Version        : %u\n", iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d Bytes\n", iph->ihl * 4);
    fprintf(logfile , "   |-Type Of Service   : 0x%02X\n", iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %u Bytes\n", ntohs(iph->tot_len)); 
    fprintf(logfile , "   |-Identification    : 0x%04X\n", ntohs(iph->id));
    /* ip_reserved_zero, ip_dont_fragment e ip_more_fragment omitted */
    fprintf(logfile , "   |-TTL               : %u\n", iph->ttl);
    fprintf(logfile , "   |-Protocol          : %u\n", iph->protocol);
    fprintf(logfile , "   |-Checksum          : 0x%04X\n", ntohs(iph->check));
    addr.s_addr = iph->saddr;
    fprintf(logfile , "   |-Source IP         : %s\n" , inet_ntoa(addr));
    addr.s_addr = iph->daddr;
    fprintf(logfile , "   |-Destination IP    : %s\n" , inet_ntoa(addr));
    
	
	fprintf(raw_logfile, "\nIP Header:\n   ");
	print_data((const u_char*) iph, (unsigned int) iph->ihl * 4);

	switch (iph->protocol) 
    {   
        case IPPROTO_TCP:  
        	strcpy(p_info.p_internet, IP); 
			strcpy(p_info.p_transport, TCP);
            tcp_handler(packet, (unsigned int) ((iph->ihl) * 4), caplen);
            break;
         
        case IPPROTO_UDP: 
        	strcpy(p_info.p_internet, IP); 
			strcpy(p_info.p_transport, UDP);
            udp_handler(packet, (unsigned int) ((iph->ihl) * 4), caplen);
            break;
        
        case IPPROTO_ICMP:  
			strcpy(p_info.p_internet, ICMP);
			strcpy(p_info.p_transport, NONE); 
            icmp_handler(packet, (unsigned int) ((iph->ihl) * 4), caplen);
            break;
        
        case IPPROTO_IGMP:
			strcpy(p_info.p_internet, IGMP); 
			strcpy(p_info.p_transport, NONE);
        	igmp_handler(packet, (unsigned int) ((iph->ihl) * 4));
        	break;
        	
        default:
        	strcpy(p_info.p_internet, IP); 
			strcpy(p_info.p_transport, OTHER);
			fprintf(logfile , "\nOther IP/Transport protocol : #%u\n", iph->protocol); 
			
			if(caplen > sizeof(struct ethhdr) + (unsigned int) iph->ihl * 4)
			{
				fprintf(raw_logfile, "\nData Payload:\n   ");
				print_data((const u_char*) iph + iph->ihl * 4, caplen - (unsigned int) sizeof(struct ethhdr) - (unsigned int) iph->ihl * 4);
			}
    }
}   


void arp_handler(const u_char* packet, unsigned int caplen)
{
	struct arpheader *arph = (struct arpheader *) (packet + sizeof(struct ethhdr));
	
	fprintf(logfile , "\nARP Header\n");
    fprintf(logfile , "   |-Hardware type      : %u\n" , ntohs(arph->htype)); 
    fprintf(logfile , "   |-Protocol type      : 0x%04X\n" , ntohs(arph->ptype)); 
    fprintf(logfile , "   |-Hardware size      : %u\n" , arph->hlen);
    fprintf(logfile , "   |-Protocol size      : %u\n" , arph->plen);	
    fprintf(logfile , "   |-Operation code     : %u\n" , ntohs(arph->oper));	

    if(arph->hlen == 6 && arph->plen == 4)
    {
    	fprintf(logfile , "   |-Sender MAC address : %02X-%02X-%02X-%02X-%02X-%02X \n", arph->sha[0], arph->sha[1], arph->sha[2], arph->sha[3], arph->sha[4], arph->sha[5]);
    	fprintf(logfile , "   |-Sender IP address  : %u.%u.%u.%u\n" , arph->spa[0], arph->spa[1], arph->spa[2], arph->spa[3]);
    	fprintf(logfile , "   |-Target MAC address : %02X-%02X-%02X-%02X-%02X-%02X\n", arph->tha[0], arph->tha[1], arph->tha[2], arph->tha[3], arph->tha[4], arph->tha[5]);	
    	fprintf(logfile , "   |-Target IP address  : %u.%u.%u.%u\n" , arph->tpa[0], arph->tpa[1], arph->tpa[2], arph->tpa[3]);
    }
    
	fprintf(raw_logfile, "\nARP Header:\n   ");
	print_data((const u_char*) arph, caplen - (unsigned int) sizeof(struct ethhdr));
}


void igmp_handler(const u_char* packet, unsigned int iph_size)
{
	struct igmp *igmph = (struct igmp *) (packet + iph_size + sizeof(struct ethhdr));

	fprintf(logfile , "\nIGMP Header\n");
    fprintf(logfile , "   |-Type     : 0x%02X\n" , igmph->igmp_type);
    fprintf(logfile , "   |-Code     : 0x%02X\n" , igmph->igmp_code);
    fprintf(logfile , "   |-Checksum : 0x%04X\n" , ntohs(igmph->igmp_cksum));
    fprintf(logfile , "   |-Group    : %s\n" , inet_ntoa(igmph->igmp_group));	
	/* This initial of header is compatible with others igmp versions */

	fprintf(raw_logfile, "\nIGMP Header:\n   ");
	print_data((const u_char*) igmph, sizeof(struct igmp));
}


void udp_handler(const u_char* packet, unsigned int iph_size, unsigned int caplen)
{
	struct udphdr *udph = (struct udphdr *) (packet + iph_size + sizeof(struct ethhdr));
	aux = (unsigned int) sizeof(struct ethhdr) + iph_size + (unsigned int) sizeof(struct udphdr);
	
	fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %u\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %u\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-Length           : %u\n" , ntohs(udph->len));
    fprintf(logfile , "   |-Checksum         : 0x%04X\n" , ntohs(udph->check));	

	fprintf(raw_logfile, "\nUDP Header:\n   ");
	print_data((const u_char*) udph, sizeof(struct udphdr));
	
	if(caplen > aux)
	{
		fprintf(raw_logfile, "\nData Payload:\n   ");
		print_data((const u_char*) udph + sizeof(struct udphdr), caplen - aux);
	}
}


void tcp_handler(const u_char* packet, unsigned int iph_size, unsigned int caplen)
{
	struct tcphdr *tcph = (struct tcphdr *) (packet + iph_size + sizeof(struct ethhdr));
	aux = (unsigned int) sizeof(struct ethhdr) + iph_size + (unsigned int) tcph->doff * 4;
	
    fprintf(logfile , "\nTCP Header\n");
    fprintf(logfile , "   |-Source Port          : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port     : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number      : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number   : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length        : %d Bytes\n", tcph->doff * 4);
	/* CWR, ECN e RES1 omitted */ 
    fprintf(logfile , "   |-Urgent Flag          : %u\n", tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %u\n", tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %u\n", tcph->psh); 
    fprintf(logfile , "   |-Reset Flag           : %u\n", tcph->rst); 
    fprintf(logfile , "   |-Synchronise Flag     : %u\n", tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %u\n", tcph->fin);
    fprintf(logfile , "   |-Window               : %u\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum             : 0x%04X\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer       : %u\n",ntohs(tcph->urg_ptr));
    
    fprintf(raw_logfile, "\nTCP Header:\n   ");
	print_data((const u_char*) tcph, (unsigned int) tcph->doff * 4);
	
	if(caplen > aux)
	{
		fprintf(raw_logfile, "\nData Payload:\n   "); 
		print_data((const u_char*) tcph + tcph->doff * 4, caplen - aux);
	}
}


void icmp_handler(const u_char* packet, unsigned int iph_size, unsigned int caplen)
{
	struct icmphdr *icmph = (struct icmphdr *)(packet + iph_size + sizeof(struct ethhdr));
	aux = (unsigned int) sizeof(struct ethhdr) + iph_size + (unsigned int) sizeof(struct icmphdr);

	fprintf(logfile , "\nICMP Header\n");
    fprintf(logfile , "   |-Type     : %u\n", icmph->type);  
    fprintf(logfile , "   |-Code     : %u\n", icmph->code);
    fprintf(logfile , "   |-Checksum : 0x%04X\n", ntohs(icmph->checksum));
    /* ID, Sequence, Gateway, MTU omitted due union structure */

	fprintf(raw_logfile, "\nICMP Header:\n   ");
	print_data((const u_char*) icmph, sizeof(struct icmphdr));
	
	if(caplen > aux)
	{
		fprintf(raw_logfile, "\nData Payload:\n   "); 
		print_data((const u_char*) icmph + sizeof(struct icmphdr), caplen - aux);
	}
}


void signal_callback(int signum)
{
	printf("\r+---------+----------+--------+----------+----------+----------+-----------+\n"); 

	if(signum != 20)
	{
		clean_screen(stderr);
		fprintf(stderr, "\n\nError: signum is NOT 20. Signum = %d\n\n", signum);
		sleep(2);
		exit(EXIT_FAILURE);
	}

	if(p_info.p_number == 0)
	{
		printf("|                           No Captured packets                            |\n+--------------------------------------------------------------------------+\n");
	}
	else if(p_info.p_number == 1)
	{
		printf("|                            1 Captured packet                             |\n+--------------------------------------------------------------------------+\n");
	}
	else
	{
		printf("|                          %06d Captured packets                         |\n+--------------------------------------------------------------------------+\n", p_info.p_number);
	}
	
	sleep(2);
	
	pcap_breakloop(handler);        /* Breaks pcap_loop() */
	pcap_dump_close(file_dumper);   /* Closes file_dumper pcap handler file */
	pcap_close(handler);            /* Closes device handler */
	
	handler = NULL;		 
	file_dumper = NULL;  

	close_files(); 
}


void print_data(const u_char* data, unsigned int length) 
{
	unsigned int i, j;
	for(i = 0; i < length; i++)
	{	
		if(!(i % 16) && i != 0)
		{
			fprintf(raw_logfile, "    ");
			for(j = i - 16; j < i ; j++)   
			{
				if(isprint(data[j]))       
					fprintf(raw_logfile, "%c", data[j]);
				else
					fprintf(raw_logfile, ".");
			}
			fprintf(raw_logfile, "\n   "); 
		}
		fprintf(raw_logfile, "%02X ", data[i]);
	

		if(i == length - 1)
		{
			for(j = 0; j < 15 - i % 16; j++)
				fprintf(raw_logfile, "   ");

			fprintf(raw_logfile, "    ");
			for(j = i - i % 16; j < length; j++)
			{
				if(isprint(data[j])) 
					fprintf(raw_logfile, "%c", data[j]);
				else
					fprintf(raw_logfile, ".");
			}
			fprintf(raw_logfile, "\n   ");
		}
	}
}


int menu(char* device_n, int* mode, int* snaplen, char* pcap_file_n, char* logfile_n, char* raw_logfile_n)
{
	int flag, i, n;
	char ch, str[16];
	pcap_if_t *alldev, *firstdev;

	if(pcap_findalldevs(&firstdev, errbuf))
	{
		clean_screen(stderr);
		fprintf(stderr, "\n\nError: %s.\n\n", errbuf);	
		sleep(2);
		exit(EXIT_FAILURE);
	}
	
	if(firstdev == NULL)
	{
		clean_screen(stderr);
		fprintf(stderr, "\n\nError: Cannot find any interface device to sniff.\n\n");	
		sleep(2);
		exit(EXIT_FAILURE);
	}
	
	clean_screen(stdout);
	
	printf("+--------------------------------------------------------------------------+\n|                            Capture Options                               |\n+--------------------------------------------------------------------------+\n");
	
	   		  
	printf("|                                                                          |\n|  Capture interface:                                                      |\n");
	
	/* For any see https://wiki.wireshark.org/SLL and man packet 7*/
	
	for(alldev = firstdev, i = 0; alldev != NULL ; i++, alldev = alldev->next)
    {
    	if(alldev->name == NULL)
    		printf("|    %3d. %-10s - [Cannot be used (invalid name)]                     |\n" , i , alldev->name);
    	else if(alldev->description == NULL)
    		printf("|    %3d. %-10s - [No description about this interface]               |\n" , i , alldev->name);
    	else            
        	printf("|    %3d. %-10s - %-51s |\n" , i , alldev->name , alldev->description); 
    }
    
    printf("|                                                                          |\n\n"); 
    flag = 1;
    do
    {       
    	printf("\033[1A\033[2K|  Enter the number of the device you want to sniff : ");
 		if(scanf("%d" , &n) != 1)
 		{
    		clean_enter(stdin);
    	}
 		else if(n >= 0 && n < i)
    		flag = 0;
    }
    while(flag);	 
    clean_enter(stdin); 
    printf("\033[1A\033[2K|  You chose interface device number : %-35d |", n); 
    
    for(alldev = firstdev, i = 0; i < n; i++, alldev = alldev->next);
    
    if(alldev == NULL || alldev->name == NULL) 
    {
    	clean_screen(stderr);
    	fprintf(stderr, "\n\nError: Cannot find the chosen interface device.\n\n");	
    	sleep(2);
		exit(EXIT_FAILURE);
    }
    else if(strlen(alldev->name) > 99)
    {
    	clean_screen(stderr);
    	fprintf(stderr, "\n\nError: Device name too long. (Probably due some error)\n\n");	
    	sleep(2);
		exit(EXIT_FAILURE);
    }
    else
    	strcpy(device_n, alldev->name);
    
    pcap_freealldevs(firstdev);
	
	printf("\n|                                                                          |\n\n"); 
	
	flag = 1;
	do
	{
		printf("\033[1A\033[2K|  Enable pomiscuous mode [Y/n] : ");
		if((ch = (char) getc(stdin)) == '\n')
		{
			*mode = 1;  
			printf("\033[1A\033[2K|  Promiscuous mode enabled.                                               |");
			flag = 0;
		}
		else if(ch == 'Y' || ch == 'y')
		{
			*mode = 1;
			clean_enter(stdin);
			printf("\033[1A\033[2K|  Promiscuous mode enabled.                                               |");
			flag = 0;
		}
		else if(ch == 'N' || ch == 'n')
		{
			*mode = 0;
			clean_enter(stdin);
			printf("\033[1A\033[2K|  Promiscuous mode disabled.                                              |");
			flag = 0;
		}
		else
			clean_enter(stdin);
	}
	while(flag);
	
	
	printf("\n|                                                                          |\n\n"); 
    flag = 1;
    do
    {     
    	printf("\033[1A\033[2K|  Snapshot length of packet (in bytes) (max: 65535) : ");
 		if(scanf("%d" , snaplen) != 1)
    		clean_enter(stdin);
 		else if(*snaplen >= 0 && *snaplen < 65536) 
    		flag = 0;
    }
    while(flag);	
    
    clean_enter(stdin); 
    sprintf(str, "%u", *snaplen);
  	strcat(str, " bytes.");
    printf("\033[1A\033[2K|  Snapshot length of packet : %-43s |", str); 

	printf("\n|                                                                          |\n");

	printf("|  PCAP file name : ");
	read_str(pcap_file_n, 26); 
	strcat(pcap_file_n, ".pcap"); 
	printf("\033[1A\033[2K|  PCAP file name : %-54s |", pcap_file_n);
	
	printf("\n|                                                                          |\n");
	
	printf("|  Logfile name : ");
	read_str(logfile_n, 27);
	strcat(logfile_n, ".txt");
	printf("\033[1A\033[2K|  Logfile name : %-56s |", logfile_n);
	
	printf("\n|                                                                          |\n\n");
	
	do
	{                            
		printf("\033[1A\033[2K|  Raw logfile name : ");
		read_str(raw_logfile_n, 27);
		strcat(raw_logfile_n, ".txt");
	}
	while(!strcmp(logfile_n, raw_logfile_n));
	
	printf("\033[1A\033[2K|  Raw logfile name : %-52s |", raw_logfile_n);
	
	printf("\n|                                                                          |\n");
    printf("|  Start capturing [Y]                         Change capture options [c]  |\n");
	printf("+--------------------------------------------------------------------------+\n");
	
	flag = 1;
	do
	{
		if((ch = (char) getc(stdin)) == '\n')
		{
			i = 1;
			flag = 0;
		}
		else if(ch == 'Y' || ch == 'y')
		{
			clean_enter(stdin);
			printf("\033[1A\033[2K");
			i = 1;
			flag = 0;
		}
		else if(ch == 'C' || ch == 'c')
		{
			clean_enter(stdin);
			printf("\033[1A\033[2K");
			i = 0;
			flag = 0;
		}
		else
		{
			printf("\033[1A\033[2K");
			clean_enter(stdin);
		}
	}
	while(flag);

	
	return i;	
}


int open_files(const char* logfile_n, const char* raw_logfile_n, const char* mode)
{
	if((logfile = fopen(logfile_n, mode)) == NULL) 
	{
		clean_screen(stderr);
		perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
		return 1;
	}
	
	if((raw_logfile = fopen(raw_logfile_n, mode)) == NULL) 
	{
		clean_screen(stderr);
		perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
		return 1;
	}

	return 0;
}


void close_files(void)
{
	fclose(logfile);
	fclose(raw_logfile);
	
	logfile = NULL;       /* Good Practice */
	raw_logfile = NULL;   /* Good Practice */
}


int open_pcapfile(const char* pcap_file_n, pcap_t* handler)
{
	if((file_dumper = pcap_dump_open(handler, pcap_file_n)) == NULL)
	{
		clean_screen(stderr);
		fprintf(stderr, "\n\nError: %s\n\n", pcap_geterr(handler));
		sleep(2); 
		return 1; 
	}
	return 0;
}


int print_header_info(const char* device_n)
{
	bpf_u_int32 netp, maskp;  

	printf("+--------------------------------------------------------------------------+\n|                           Capture Information                            |\n+--------------------------------------------------------------------------+\n");
  
	printf("| Network device  : %-55s|\n", device_n);
	
	if(pcap_lookupnet(device_n, &netp, &maskp, errbuf)) 
	{
		clean_screen(stderr);
		fprintf(stderr, "\n\nError: %s.\n\n", errbuf);
		sleep(2);
		return 1;
	}
	
	addr.s_addr = netp;
	printf("| Network address : %-55s|\n", inet_ntoa(addr));
	addr.s_addr = maskp;
	printf("| Netmask         : %-55s|\n+--------------------------------------------------------------------------+\n", inet_ntoa(addr));

	printf("| Packet  |  Time    | Packet | Captured |             Layers              |\n| number  | elapsed  | Length |  Length  |   Link   | Internet | Transport |\n+---------+----------+--------+----------+----------+----------+-----------+\n");

	return 0;
}


int end_menu(const char* logfile_n, const char* raw_logfile_n)
{
	int flag;
	char merged_file_n[32], ch;

	clean_screen(stdout);

	printf("+--------------------------------------------------------------------------+\n|                              File Options                                |\n+--------------------------------------------------------------------------+\n|                                                                          |\n\n");

	flag = 1;
	do
	{
		printf("\033[1A\033[2K|  Merge the %s and %s [Y/n] : ", logfile_n, raw_logfile_n);
		if((ch = (char) getc(stdin)) == '\n')
		{                           
			do
			{
				printf("\033[1A\033[2K|  Merged file name : ");
				read_str(merged_file_n, 27); 
				strcat(merged_file_n, ".txt"); 
			}
			while(!strcmp(merged_file_n, logfile_n) || !strcmp(merged_file_n, raw_logfile_n));
			
			printf("\033[1A\033[2K|  Merged file name : %-52s |", merged_file_n);
			printf("\n|                                                                          |\n");
			
			printf("|  Merging...                                                              |\n");

			if(merge_file(merged_file_n, logfile_n, raw_logfile_n))
				return 1;
				
			printf("\033[1A\033[2K|  Merging... Done.                                                        |\n");
			
			flag = 0;
		}
		else if(ch == 'Y' || ch == 'y')
		{
			clean_enter(stdin);
			do
			{
				printf("\033[1A\033[2K|  Merged file name : ");
				read_str(merged_file_n, 27); 
				strcat(merged_file_n, ".txt"); 
			}
			while(!strcmp(merged_file_n, logfile_n) || !strcmp(merged_file_n, raw_logfile_n));
			
			printf("\033[1A\033[2K|  Merged file name : %-52s |", merged_file_n);
			printf("\n|                                                                          |\n");
			
			printf("|  Merging...                                                              |\n");
			
			if(merge_file(merged_file_n, logfile_n, raw_logfile_n))
				return 1;
				
			printf("\033[1A\033[2K|  Merging... Done.                                                        |\n");
			
			flag = 0;
		}
		else if(ch == 'N' || ch == 'n')
		{
			clean_enter(stdin);
			
			printf("\033[1A\033[2K|  Processing %s ... %*c |\n", logfile_n, (int) (55 - strlen(logfile_n)) , ' ');  
			
			if(clean_file(logfile_n))
				return 1;
			
			printf("\033[1A\033[2K|  Processing %s ... Done.%*c |\n", logfile_n, (int) (50 - strlen(logfile_n)) , ' '); 
				
			printf("|  Processing %s ... %*c |\n", raw_logfile_n, (int) (55 - strlen(raw_logfile_n)) , ' ');
			
			if(clean_rawfile(raw_logfile_n))
				return 1;
			
			printf("\033[1A\033[2K|  Processing %s ... Done.%*c |\n", raw_logfile_n, (int) (50 - strlen(raw_logfile_n)) , ' ');	
				
			flag = 0;
		}
		else
			clean_enter(stdin);
	}
	while(flag);

	printf("|                                                                          |\n+--------------------------------------------------------------------------+\n\n");

	sleep(2);
	
	clean_screen(stdout);
	return 0;
}


void clean_screen(FILE* stream)
{
	fprintf(stream, "\033[2J\033[0;0H");
}


int merge_file(char* merged_file_n, const char* logfile_n, const char* raw_logfile_n)
{
	int flag_raw, flag, ch, r;

	FILE* merged = NULL;

	if(open_files(logfile_n, raw_logfile_n, "r"))
		return 1;

	flag = flag_raw = 0;

	if((merged = fopen(merged_file_n, "w")) == NULL)
	{
		clean_screen(stderr);
		perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
		return 1;
	}


	while((ch = getc(logfile)) != EOF)
	{
		if(ch == 7)
		{
			ch = getc(logfile);
		
			if(flag) 
			{	
				while((r = getc(raw_logfile)) != EOF)	
				{		
					if(r == 7)
					{
						if(flag_raw)
							break;
					
						r = getc(raw_logfile);
					}
				
					flag_raw = 1;
					putc(r, merged);
				}
			}
		}
		
		flag = 1;
		putc(ch, merged);
	}

	while((r = getc(raw_logfile)) != EOF)	
	{		
		if(r == 7)
		{
			r = getc(raw_logfile);
		}
		putc(r, merged);
	}
	
	fclose(merged);
	close_files();
	
	if(remove(raw_logfile_n))
	{
		clean_screen(stderr);
       	perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
       	return 1;
	}

	if(remove(logfile_n))
	{
		clean_screen(stderr);
       	perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
       	return 1;
	}
	
	return 0;
}


int clean_file(const char* file_n)
{
	int c;
	
	FILE* old = NULL;
	FILE* new = NULL;


	if((old = fopen(file_n, "r")) == NULL)  
	{
		clean_screen(stderr);
		perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
		return 1;
	}

	if((new = fopen(TEMPFILE_N, "w")) == NULL)  
	{
		clean_screen(stderr);
		perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
		return 1;
	}


	while((c = getc(old)) != EOF) 
	{
		if(c != 7)
			putc(c, new);
	}
	
	
	fclose(old);
	fclose(new);


	if(remove (file_n))
	{
		clean_screen(stderr);
		perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
       	return 1;
	}
	
	if(rename (TEMPFILE_N, file_n))
	{
		clean_screen(stderr);
		perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
       	return 1;
	}

	return 0;
}


int clean_rawfile(const char* rawfile_n)
{
	int c, i;
	
	FILE* old = NULL;
	FILE* new = NULL;

	i = 0;

	if((old = fopen(rawfile_n, "r")) == NULL)  
	{
		clean_screen(stderr);
		perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
		return 1;
	}

	if((new = fopen(TEMPFILE_N, "w")) == NULL)  
	{
		clean_screen(stderr);
		perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
		return 1;
	}


	while((c = getc(old)) != EOF) 
	{
		if(c == 7)
			fprintf(new, "***************************[Packet #%06d]****************************\n\n", ++i);
		else
			putc(c, new);
	}
	
	
	fclose(old);
	fclose(new);


	if(remove(rawfile_n))
	{
		clean_screen(stderr);
       	perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
       	return 1;
	}
	
	if(rename(TEMPFILE_N, rawfile_n))
	{
		clean_screen(stderr);
		perror("\n\nError");
		fprintf(stderr, "\n\n");
		sleep(2);
       	return 1;
	}

	return 0;
}

/*
 * Lê len caracteres e coloca '\0' na posição len + 1. 
 * Obs: Se alocou ex: char str[3] deve passar como parâmetro read_str(str, 2);
 *      Sempre o tamanho alocado menos 1.
 */
void read_str(char *str, int len)
{
	register int i = 1;
	register char c;

	/* Elimina os espacos em branco, enters e EOFs do comeco*/
	while((c = (char) getc(stdin)) == ' ' || c == '\n' || c == EOF); /* tem que pegar o EOF tbm !!!*/
	*str = c; /* O i iniciado em 1 é devido a este primeiro caracter (de posição 0) */
	
	/* Faz a leitura segura(eu acho)*/
	while(i < len && (*(str+i) = (char) getc(stdin)) != '\n' && *(str+i) != EOF) i++; /*a ordem importa !!*/
	*(str+i) = '\0'; /*Finaliza com NULL*/
	
	/* Limpa o buffer caso estourar o tamanho maximo*/
	if(i >= len) /* Teoricamente este maior nunca vai ocorrer.. somente o igual */
		while((c = (char) getc(stdin)) != '\n' && c != EOF);
}

void clean_enter(FILE* stream)
{
	while(getc(stream) != '\n'); 
}











