#include<winsock2.h>
#include<windows.h>
#include<ws2tcpip.h>
#include<stdio.h>
#include<stdlib.h>

// Msn Sniffer header =) thx Delikon for macro.

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) // THX :)

typedef struct tcpheader {
unsigned short int sport;
unsigned short int dport;
unsigned int th_seq;
unsigned int th_ack;
unsigned char th_x2:4;
unsigned char th_off:4;
unsigned char Flags;
unsigned short int th_win;
unsigned short int th_sum;
unsigned short int th_urp;
};

struct ipheader {
 unsigned char ip_hl:4, ip_v:4;
 unsigned char ip_tos;
 unsigned short int ip_len;
 unsigned short int ip_id;
 unsigned short int ip_off;
 unsigned char ip_ttl;
 unsigned char ip_p;
 unsigned short int ip_sum;
 unsigned int ip_src;
 unsigned int ip_dst;
};
