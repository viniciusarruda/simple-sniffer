#include <arpa/inet.h>   /* To use inet_ntoa() */
#include <ctype.h> /* This header declares a set of functions to classify and transform individual characters. (isprint) */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h> /* To use signal() */
#include <string.h>

#include <net/ethernet.h>     /* Provides declarations for ethernet header */  
#include <netinet/ip.h>       /* Provides declarations for ip header       */
#include <netinet/ip_icmp.h>  /* Provides declarations for icmp header     */
#include <netinet/igmp.h>     /* Provides declarations for igmp header     */
#include <netinet/tcp.h>      /* Provides declarations for tcp header      */
#include <netinet/udp.h>      /* Provides declarations for udp header      */


#define MAXNUMBYTES2CAPTURE 65535 /* 65536 (2^16) (0 - 65535)  Size of package (In bytes) that will be saved on package */

#define	ETH_TYPE_IP 2048	    /* Same as ETHERTYPE_IP 0x0800, but in decimal. (IP protocol) */
#define	ETH_TYPE_ARP 2054	    /* Same as ETHERTYPE_ARP 0x0806, but in decimal. (Address resolution) */
#define	ETH_TYPE_REVARP 32821	/* Same as ETHERTYPE_REVARP 0x8035, but in decimal. (Reverse ARP) */


#define ETHERNET "ETHERNET"
#define WIRELESS "WIRELESS"
#define IP       "   IP   "
#define ARP      "  ARP   "
#define RARP     "  RARP  "
#define ICMP     "IP/ICMP "
#define TCP      "  TCP   "
#define UDP      "  UDP   "
#define IGMP     "IP/IGMP "
#define UNKNOWN  " ------ "
#define OTHER    " OTHER  "
#define NONE     "  NONE  "

/* ARP Header, (assuming Ethernet+IPv4)            */ 
struct arpheader { 
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


void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet); /* I understood bytes(changed to packet) ~ payload (Actually, */
																			    /* is the "holl" packet, Payload is only the middle of the    */
																			 	/* packet and not all of it.. or Am I wrong ?) */
void signal_callback(int signum);

void ethernet_handler(const u_char* packet, unsigned int caplen);
void ip_handler(const u_char* packet, unsigned int caplen);
void arp_handler(const u_char* packet, unsigned int caplen);
void icmp_handler(const u_char* packet, unsigned int iph_size, unsigned int caplen);
void igmp_handler(const u_char* packet, unsigned int iph_size);
void tcp_handler(const u_char* packet, unsigned int iph_size, unsigned int caplen);
void udp_handler(const u_char* packet, unsigned int iph_size, unsigned int caplen);

void print_data(const u_char* data, unsigned int length);

/* They will be really global varable ? */
FILE* logfile = NULL;              /* Good practice */
FILE* raw_logfile = NULL;          /* Good practice */
unsigned int aux;                  /* To help sums around the code */
long int init_time;                /* Stores the initial time. */
pcap_t* handler = NULL;            /* Good practice, pois handler tem lixo em seu conteudo inicialmente, então este ponteiro "aponta" para memoria desconhecida. */ 
pcap_dumper_t* file_dumper = NULL; /* to use with pcap_dump, receive a pointer from pcap_dump_open */
struct in_addr addr;               /* To use with inet_ntoa() */ 

/* Packet Information */
struct 
{
	unsigned int p_number;
	char p_time[9];
	char p_link[9];           /* Ethernet, Wireless, Other */
	char p_internet[9];       /* Ip, Arp, Rarp, Icmp, Igmp, Other */
	char p_transport[9];      /* Tcp, Udp, Other */
} p_info;


/* Counters */
/* seria uma boa colocar todos esses contadores em uma struct, fica mais bem organizado */
/* Datalink counters */
int ether_count = 0;
int wire_count = 0;
int other_datalink_count = 0;

/* Network counters */	
int ip_count = 0;
int arp_count = 0;
int rarp_count = 0;
int other_net_count = 0;

/* Transport counters */
int icmp_count = 0;
int tcp_count = 0;
int udp_count = 0;
int igmp_count = 0;
int other_transp_count = 0;


int 
main(int argc, char* argv[])
{
	int datalink_value, i; /*unsigned char *user;  Will do nothing (create a u_char and print the size and put negative numbers to it)*/
	char errbuf[PCAP_ERRBUF_SIZE]; /* After testing use memset to put zeros on it. */
	const char* device = "wlan0"; /* colocar NULL */
	bpf_u_int32 netp, maskp;  /* IPv4 network number and netmask. */
	struct timeval init; /* To use gettimeofday, to get the initial time. */
	char* file = "pcapfile.pcap";
	pcap_if_t *alldev;
	
	p_info.p_number = 0; 
	
	/* Gets the initial time */
	gettimeofday(&init, NULL);
	init_time = init.tv_sec;
	
	
	
	/*****************************************************************************************************/

	/*
	 dar o free all devs so ler o man 
	if(pcap_findalldevs(&alldev, errbuf))
	{
		fprintf(stderr, "Erro: %s.\n", errbuf);	
		exit(EXIT_FAILURE);
	}
	
	for(; alldev != NULL ; alldev = alldev->next)
    {
        printf("%d. %s - %s\n" , i , alldev->name , alldev->description);
        if(alldev->name != NULL)
        {
        	malloc devs acho que sim, ou fazer devs[100][100]?
            strcpy(devs[i] , alldev->name);
        }
        i++;
    }
    
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n); fazer validacao dos dados
    device = devs[n];
	
	struct pcap_if {
	struct pcap_if *next;
	char *name;		
	char *description;	
	struct pcap_addr *addresses;
	bpf_u_int32 flags;	
	};
	*/
	
	/*****************************************************************************************************/
	
	
	if((logfile = fopen("logfile.txt", "w")) == NULL) /* colocoar todos os erros no stderr */
	{
		fprintf(stderr, "Erro ao abrir logfile.txt");
		exit(EXIT_FAILURE);
	}
	
	if((raw_logfile = fopen("raw_logfile.txt", "w")) == NULL) /* colocoar todos os erros no stderr */
	{
		fprintf(stderr, "Erro ao abrir logfile.txt");
		exit(EXIT_FAILURE);
	}
                            	
	printf("+--------------------------------------------------------------------------+\n|                           Capture Information                            |\n+--------------------------------------------------------------------------+\n");
  
	printf("| Network device : %-56s|\n", device);
	
	if(pcap_lookupnet(device, &netp, &maskp, errbuf)) /* errbuf - In C arrays decay into pointers when passed by parameter. */
	{
		fprintf(stderr, "Erro: %s.\n", errbuf);
		exit(EXIT_FAILURE); 
	}
	
	addr.s_addr = netp;
	printf("| Network address: %-56s|\n", inet_ntoa(addr));
	addr.s_addr = maskp;
	printf("| Netmask        : %-56s|\n+--------------------------------------------------------------------------+\n", inet_ntoa(addr));
	
	printf("| Packet  |  Time    | Packet | Captured |             Layers              |\n| number  | elapsed  | Length |  Length  |   Link   | Internet | Transport |\n+---------+----------+--------+----------+----------+----------+-----------+\n");

	/*
	printf("| Packet  |  Time    |             Layers              |\n
	        | number  | elapsed  |   Link   | Internet | Transport |\n
	        +---------+----------+----------+----------+-----------+\n");
	
	printf("| Packet  |  Time    | Packet | Captured |             Layers              |\n
	        | number  | elapsed  | Length |  Length  |   Link   | Internet | Transport |\n
			+---------+----------+--------+----------+----------+----------+-----------+\n");
	 
	printf("| Packet  |  Time    | Length (in bytes) |             Layers              |\n
	        | number  | elapsed  | Packet | Captured |   Link   | Internet | Transport |\n

	
	
	printf("| Packet  |  Time    | Packet | Captured |             Layers              |\n
	        | number  | elapsed  | Length (in bytes) |   Link   | Internet | Transport |\n
	 */
	
	/* Open device to capture the packages */
	/* pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf); */
	handler = pcap_open_live(device, MAXNUMBYTES2CAPTURE, 1, 1000, errbuf);
	/* fazer a validação se handler é null ou não ! se for mostra o errbuf. testar esse negocio do memset(zero)(necessario ?) */
	
	/*
		"...To have an idea we can examine what other snifers do.
		Tcpdump uses a value of 1000, dsniff uses 512 and ettercap
		distinguishes between different operating systems using
		0 for Linux or OpenBSD and 10 for the rest..." (http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf)
	*/
	/*
	pcap_open_live() returns a pcap_t * on success and NULL on failure. If NULL is returned, errbuf is filled in with an appropriate error 		  message. errbuf may also be set to warning text when pcap_open_live() succeeds; to detect this case the caller should store a zero-length string in errbuf before calling pcap_open_live() and display the warning to the user if errbuf is no longer a zero-length string. errbuf is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars.  
		Isso significa que caso for sucesso, e for ver a mensagem de errbuf, tenho que previamente ter zerado sua memoria, caso contrario,
		posso deixar sem zerar.
		isso porque se pode verificar se deu erro verificando errbuf. Deu erro caso não for tudo zero. (acho que não preciso)
	*/
	
	
	/* Register signal and signal handler */
	if(signal(SIGTSTP, signal_callback) == SIG_ERR)  /* SIGTSTP for ctrl + z and SIGINT for ctrl + c*/
	{
		fprintf(stderr, "Error using signal function.\n");
		exit(EXIT_FAILURE);
	}
	
	
	/* pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname); */
	file_dumper = pcap_dump_open(handler, (const char*) file);
	
	if(file_dumper == NULL)
	{
		fprintf(stderr, "\nERRO AO ABRIR A PCAP FILE: %s\n\n", pcap_geterr(handler)); 
		exit(EXIT_FAILURE);  
	}
	
	/* Validates the datalink value (Because callback receives just an unsigned char (0 - 255)) */
	if((datalink_value = pcap_datalink(handler)) > 255) /* o any aqui pode dar errado n ? */
	{
		datalink_value = 255;  /* Its a flag (avoiding conversion error) !!! NOT BLUETOOTH (bluetooth it is represented by 255 code) */	
	}
	
	/* Loop forever */
	/* int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user); */
	pcap_loop(handler, -1, callback, (u_char*) &datalink_value); /* After testing, get the int returned value. */
	
	return 0;
}

/*Every time that a packet is captured by net card, the callback function will be called !*/
void 
callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{
	long int elapsed;
	
	pcap_dump((u_char*)file_dumper, h, packet); /* vai ser influenciado pelo MAXBYTES2CAPTURE (como visto no pcapfile no wireshark) */
	
	p_info.p_number++; /* pcap_stats tem contador, porem testa-lo, pois pode ou não funcionar */
	
	fprintf(logfile , "********************[Init of Packet #%06d]********************\n", p_info.p_number);
	fprintf(raw_logfile , "#%06d", p_info.p_number);
	elapsed = h->ts.tv_sec - init_time;
	sprintf(p_info.p_time, "%02ld:%02ld:%02ld", elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60);
	
	
	/* analisar se é melhor deixar caplen global, assim na hora de "colocar a bandeija" nao tem que reservar memoria e ocupar processamento */
	if(*user == DLT_EN10MB) 
	{
		ether_count++; /* pensa ! se é fixo, não é necesário*/
		strcpy(p_info.p_link, ETHERNET); 
		ethernet_handler(packet, h->caplen); 
	}
	else
	{
		other_datalink_count++;
		strcpy(p_info.p_link, OTHER);
		strcpy(p_info.p_internet, UNKNOWN);
		strcpy(p_info.p_transport, UNKNOWN);
		fprintf(logfile , "\nOther link protocol : #%d\n", *user);  /* http://www.tcpdump.org/linktypes.html (list of linktypes) */
		fprintf(raw_logfile, "\nOther link protocol : #%d\n", *user);	
		fprintf(raw_logfile, "\nData Dump:\n");
		print_data(packet, h->caplen);
	}
	
	fprintf(logfile , "\n\n");
	fprintf(raw_logfile , "\n");
	printf("| #%06d | %s | %06d |  %06d  | %s | %s | %s  |\n", p_info.p_number, p_info.p_time, h->len, h->caplen, p_info.p_link, p_info.p_internet, p_info.p_transport);
}


void ethernet_handler(const u_char *packet, unsigned int caplen)
{
	struct ethhdr *eth = (struct ethhdr *) packet; /* Magic Casting !! */  /* VER A STRUCT DO ETHHDR !!! */
	unsigned short protocol = ntohs(eth->h_proto); /* Como o -Wconversion não deu warning sobre a conversão implicita, então a conversão não
													  altera em nada os valores (são tipos equivalentes) */ 
													  /* unsigned short is the same that unsigned short int (font: stackoverflow) */
    
    
    /* Trocar sdtout por logfile */
    fprintf(logfile , "\nEthernet Header\n"); /* Porque estava .2X e não X ? */  /*0 garante preencher c/ 0 e 2 duas casas, colocar 02X*/
    fprintf(logfile , "   |-MAC Destination Address : %02X-%02X-%02X-%02X-%02X-%02X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-MAC Source Address      : %02X-%02X-%02X-%02X-%02X-%02X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol                : 0x%04X \n", protocol);
    /* Because of big and little endian, the ethernet protocol IP number is printed as 8
       it should be 0x0800 that is stored as 00 08 on PC (ntohs() get out the little or big endian and X prints in hexadecimal 2048=0x0800) */   

	
	fprintf(raw_logfile, "\n\nETHERNET Header:\n"); /* Size of ethernet header is fixed (for ipv4) */
	print_data((const u_char*) eth, sizeof(struct ethhdr));

	switch(protocol) /* nesses switchs pode colocar o quando de protocolos desejar sem colocar funcao handler (so enfeite no stdout) */
	{
		case ETH_TYPE_IP:
			ip_count++;
			ip_handler(packet, caplen);
			break;
			
		case ETH_TYPE_ARP:  /* RARP obsoleto (hj eh o dhcp feito pelo udp)! */
			arp_count++;
			strcpy(p_info.p_internet, ARP);  /* A string literal already includes the terminating \0 */
			strcpy(p_info.p_transport, NONE);
			arp_handler(packet, caplen);
			break;
			
		default:
			other_net_count++;	
			strcpy(p_info.p_internet, OTHER);
			strcpy(p_info.p_transport, UNKNOWN); /* Nao se sabe se existe transporte.. então.. UNKNOWN */
			fprintf(logfile , "\nOther network protocol : #0x%04X\n", protocol);
			fprintf(raw_logfile, "\nOther network protocol : #0x%04X\n", protocol);					
			
			if(caplen > sizeof(struct ethhdr))
			{
				fprintf(raw_logfile, "\nData Dump:\n");
				print_data((const u_char*) eth + sizeof(struct ethhdr), caplen - (unsigned int) sizeof(struct ethhdr));
			}		  							  						  
	}
}


void ip_handler(const u_char *packet, unsigned int caplen)
{
	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr)); /* iphdr ~ IP Header */ /* Pointer aritmetic. */ 
	
    fprintf(logfile , "\nIP Header\n");
    fprintf(logfile , "   |-IP Version        : %u\n", iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d Bytes\n", iph->ihl * 4);
    fprintf(logfile , "   |-Type Of Service   : 0x%02X\n", iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %u Bytes(Size of Packet)\n", ntohs(iph->tot_len)); /* pode ser que total length seja diferent
                                                                                                       do total que foi capturado (caplen)
                                                                                                       assim pode dar segfault se usar total
                                                                                                       ao inves de caplen */ 
    fprintf(logfile , "   |-Identification    : 0x%04X\n", ntohs(iph->id));
    /* ip_reserved_zero, ip_dont_fragment e ip_more_fragment omitidos */
    fprintf(logfile , "   |-TTL               : %u\n", iph->ttl);
    fprintf(logfile , "   |-Protocol          : %u\n", iph->protocol);
    fprintf(logfile , "   |-Checksum          : 0x%04X\n", ntohs(iph->check));
    addr.s_addr = iph->saddr;
    fprintf(logfile , "   |-Source IP         : %s\n" , inet_ntoa(addr));
    addr.s_addr = iph->daddr;
    fprintf(logfile , "   |-Destination IP    : %s\n" , inet_ntoa(addr));
    
	
	/* Interessante: Campo de bit !! IHL é em DWORDS, o máximo são 60 bytes, ou seja, 15 * 4 bytes (1 DWORD == 4 Bytes).
     *               Abaixo (Caso big endian só inverte) Separa 4 bits de um _u8 (8 bits ~ 1 unsigned char) pois 4 bits tem como numero
     *               máximo 15, então este valor é multiplicado pos 4, e resulta no máximo header que é de 60 bytes.
     *               Isso que é economizar memória, neste caso (Pacote de dados), transmissão e velocidade.
     * struct iphdr {
	 * #if defined(__LITTLE_ENDIAN_BITFIELD)
	 *         __u8    ihl:4,
	 *                 version:4;
     */
	
	fprintf(raw_logfile, "\nIP Header:\n");
	print_data((const u_char*) iph, (unsigned int) iph->ihl * 4);

	switch (iph->protocol) /* Check the Protocol and do accordingly... */
    {   
        case IPPROTO_TCP:  /* TCP Protocol */
        	tcp_count++;
        	strcpy(p_info.p_internet, IP); 
			strcpy(p_info.p_transport, TCP);
            tcp_handler(packet, (unsigned int) ((iph->ihl) * 4), caplen);
            break;
         
        case IPPROTO_UDP: /* UDP Protocol */ 
        	udp_count++;
        	strcpy(p_info.p_internet, IP); 
			strcpy(p_info.p_transport, UDP);
            udp_handler(packet, (unsigned int) ((iph->ihl) * 4), caplen);  /* Por causa do 4, converte para int, ai dps tenho que converter para unsig.*/
            break;
        
        case IPPROTO_ICMP:  /* ICMP Protocol */
        	icmp_count++;
			strcpy(p_info.p_internet, ICMP);
			strcpy(p_info.p_transport, NONE); 
            icmp_handler(packet, (unsigned int) ((iph->ihl) * 4), caplen); /* *4 pois esta em DWORD e não bytes (DWORD == 4 bytes = 32 bits)  */
            break;
        
        case IPPROTO_IGMP:
        	igmp_count++;
			strcpy(p_info.p_internet, IGMP); 
			strcpy(p_info.p_transport, NONE);
        	igmp_handler(packet, (unsigned int) ((iph->ihl) * 4));
        	break;
        	
        default:
        	other_transp_count++;
        	strcpy(p_info.p_internet, IP); 
			strcpy(p_info.p_transport, OTHER);
			fprintf(logfile , "\nOther IP/Transport protocol : #%u\n", iph->protocol); 
			fprintf(raw_logfile, "\nOther IP/Transport protocol : #%u\n", iph->protocol);
			
			if(caplen > sizeof(struct ethhdr) + (unsigned int) iph->ihl * 4)
			{
				fprintf(raw_logfile, "\nData Dump:\n");
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
    
	fprintf(raw_logfile, "\nARP Header:\n");
	print_data((const u_char*) arph, caplen - (unsigned int) sizeof(struct ethhdr));
}


void igmp_handler(const u_char* packet, unsigned int iph_size)
{
	struct igmp *igmph = (struct igmp *) (packet + iph_size + sizeof(struct ethhdr));

	/* de qualquer forma, v2 e v3 possuiem este mesmo começo ! */
	fprintf(logfile , "\nIGMP Header\n");
    fprintf(logfile , "   |-Type     : 0x%02X\n" , igmph->igmp_type);
    fprintf(logfile , "   |-Code     : 0x%02X\n" , igmph->igmp_code);
    fprintf(logfile , "   |-Checksum : 0x%04X\n" , ntohs(igmph->igmp_cksum));
    fprintf(logfile , "   |-Group    : %s\n" , inet_ntoa(igmph->igmp_group));	

	fprintf(raw_logfile, "\nIGMP Header:\n");
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

	fprintf(raw_logfile, "\nUDP Header:\n");
	print_data((const u_char*) udph, sizeof(struct udphdr));
	
	if(caplen > aux)
	{
		fprintf(raw_logfile, "\nData Payload:\n");
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
    fprintf(logfile , "   |-Header Length        : %d BYTES\n", tcph->doff * 4);
	/* CWR, ECN e RES1 omitidos (não está definido nesta struct. Porque ? ) só olhar no prorpio diretorio /usr/include */ 
    fprintf(logfile , "   |-Urgent Flag          : %u\n", tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %u\n", tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %u\n", tcph->psh); 
    fprintf(logfile , "   |-Reset Flag           : %u\n", tcph->rst); 
    fprintf(logfile , "   |-Synchronise Flag     : %u\n", tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %u\n", tcph->fin);
    fprintf(logfile , "   |-Window               : %u\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum             : 0x%04X\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer       : %u\n",ntohs(tcph->urg_ptr));
    
    fprintf(raw_logfile, "\nTCP Header:\n");
	print_data((const u_char*) tcph, (unsigned int) tcph->doff * 4);
	
	if(caplen > aux)
	{
		fprintf(raw_logfile, "\nData Payload:\n");  /* concertar isso !! */
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
    
    /*
   	Não modificar o icmp.. esse comentario é só para saber do que esta sendo omitido e o motivo disso.
    proxima versão, sem comentarios.
    
    fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->un.echo.id));
    fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->un.echo.sequence));
    fprintf(logfile , "   |-Gateway  : %d\n",ntohs(icmph->un.gateway));
	ISSO VAI DAR UM SWITCH MUITO GRANDE (melhor caso 1, pior caso ~50)
    fprintf(logfile , "   |-MTU      : %d\n",ntohs(icmph->un.frag.mtu));
    
     As outras informações que vem no icmp, como id, sequence e tal, podem estar presentes ou não, existem no total 5 campos
     nesta situação, então preferi não mostrar pois ia ter que colocar alguns ifs a mais deixando o programa mais lento 
     */

	fprintf(raw_logfile, "\nICMP Header:\n");
	print_data((const u_char*) icmph, sizeof(struct icmphdr));
	
	if(caplen > aux)
	{
		/* Em alguns casos, como no PING, extiste dados após o header, tanto é que no ping pode se escolher o comprimento de cada mensagem. */
		fprintf(raw_logfile, "\nData Payload:\n");  /* Esse data payload esta sem os (id, sequence) ou (gateway) ou  (unused, MTU)*/
		print_data((const u_char*) icmph + sizeof(struct icmphdr), caplen - aux);
	}
}


/*
    estatistica basica: http://www.tcpdump.org/manpages/pcap_stats.3pcap.html
    No final de tudo, verificar possiveis erros, como retorno de funções que podem ter flags indicando erro.
    int pcap_stats(pcap_t *p, struct pcap_stat *ps); me parece não ser confiavel.. testar ela bem

*/


void signal_callback(int signum)
{
	printf("\r+---------+----------+--------+----------+----------+----------+-----------+\n");

	if(signum != 20)
		printf("\nERRO: SIGNUM != 20 (SIGTSTP)\n\n");  /* just for debug, always SIGTSTP has to be 20 */
		
	printf("\rEnding the program...(SIGNUM: %d)\n\n", signum); /* The '\r' "eats" the '^Z' on stdout. */
	pcap_breakloop(handler);        /* Breaks pcap_loop() */
	pcap_dump_close(file_dumper);   /* Closes file_dumper pcap handler file */
	pcap_close(handler);            /* Closes device handler */
	fclose(logfile);
	fclose(raw_logfile);
	
	handler = NULL;		  /* This occurs when a package is still being captured and the user types ctrl+z more than once. */
	file_dumper = NULL;   /* To avoid double free by the user. */	
	logfile = NULL;       /* Good Practice */
	raw_logfile = NULL;   /* Good Practice */

	/* When dump data into logfile, do: fclose(logfile) and set logfile to NULL */
	/* "if the value of the operand of delete is the null pointer the operation has no effect." (ISO/IEC 14882:2003(E) 5.3.5.2) */	
}


void print_data(const u_char* data, unsigned int length)  /* length in bytes */ /* Fazer o uso do const quando for adequado (verificar o código) !!! */
{
	unsigned int i, j;
	for(i = 0; i < length; i++)
	{	
		if(!(i % 16) && i != 0)
		{
			fprintf(raw_logfile, "\t");
			for(j = i - 16; j < i ; j++)   /* ICMP Header:
											  08 00 64 C9 20 72 00 01    	..d. r..    aqui ocorreu de imprimir o espaço que eh 20(em hexa)*/
			{
				if(isprint(data[j]))       /* isprint inclui espaço, isgraph exclui espaço, pode haver nessecidade de excluir espaço pois n existe
											e dependendo pode interpretar como espaço e ficar ruim (maiss rapido funcao ou manual ? isprint asc)
											 ou verificar se esta dentro da ascii >128 <65 (chutei numeros) por ser mais rapido e nao ter que 
											 chamar mais uma funçao gastando mais memoria(bandeja) e processamento */
					fprintf(raw_logfile, "%c", data[j]);
				else
					fprintf(raw_logfile, ".");
			}
			fprintf(raw_logfile, "\n"); 
		}
		fprintf(raw_logfile, "%02X ", data[i]);
	

		if(i == length - 1)
		{
			for(j = 0; j < 15 - i % 16; j++)
				fprintf(raw_logfile, "   ");

			fprintf(raw_logfile, "\t");
			for(j = i - i % 16; j < length; j++)
			{
				if(isprint(data[j])) 
					fprintf(raw_logfile, "%c", data[j]);
				else
					fprintf(raw_logfile, ".");
			}
			fprintf(raw_logfile, "\n");
		}
	}
}








