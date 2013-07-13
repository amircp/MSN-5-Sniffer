/* MSN Sniffer v1 coded by Amir Canto for Linux and Windows
 * this sniffer was made for educational purposes only ;)
 * compile in windows with vc++: cl msnsniff.cpp ws2_32.lib
 * 
 *
 * @TODO Adapt to Linux and compile with gcc
 * @Notes Only works for MSN Messenger 5, but this an example about "how to create an sniffer under windows"
 * 				very useful for educational purposes... please don't spy anybody ;-)
 *
 * 	Tested ONLY under Windows XP (and works very fine ;-)).
 */



#include "headers.h"
#define MSN_PORT 1863

void /*LPSTR*/ ExtractPacket(char *cMsnPacket);

int main(int argc, char **argv) {

	if(argc<2) {
		printf("MSN Sniffer v1 Coded by Amir Canto\n");
		printf("usage: %s <ethernet interface>",argv[0]);
	} else {
        

	SOCKET sock;
	SOCKADDR_IN sain;
	DWORD dwBytes;
	char cBuffer[65535] = {0};
	char *packet=NULL;
	int io = 1;
	int len=0;
	LPTSTR szMsntalk;

  #ifdef WIN32
        WSAData ws;
				WSAStartup(MAKEWORD(2,1),&ws);
  #endif
	sock = socket(AF_INET,SOCK_RAW,IPPROTO_IP);
        
  #ifdef WIN32
    
    	if(sock==SOCKET_ERROR) ExitProcess(0);
  #else
        if(sock==0)exit(-1);
  #endif
	
	sain.sin_family = AF_INET;
	sain.sin_port = htons(6000);
	sain.sin_addr.S_un.S_addr = inet_addr(argv[1]); // interfaces[argv[1]];
  printf("Binding on interface... \n");
  bind(sock,(SOCKADDR*)&sain,sizeof(sain));
	WSAIoctl(sock,SIO_RCVALL,&io,sizeof(io),NULL,0,&dwBytes,NULL,NULL);
  printf("Using WSAIoctl\n");
	struct tcpheader *pTCPHeader;
	struct ipheader  *pIPHeader;
	pIPHeader = (struct ipheader *)cBuffer;
	pTCPHeader = (struct tcpheader *)(cBuffer + sizeof(struct ipheader));
  printf("\nSniffing TCP packet's...\n");
	while(1)
	{
	    memset(cBuffer,0,sizeof(cBuffer));
			recv(sock,cBuffer,sizeof(cBuffer),0);
	    len =(ntohs(pIPHeader->ip_len)-(sizeof(struct ipheader)+sizeof(struct tcpheader)));	
			if((pIPHeader->ip_p==IPPROTO_TCP)&&(len!=0)){
				packet = (char *)&cBuffer[sizeof(struct ipheader)+sizeof(struct tcpheader)];
		    char *pointer,*pointer1,*pointer3;
		   	if((pointer=strstr(packet,"MSG")) && (pointer1=strstr(packet,"text/plain"))) {
  					ExtractPacket(pointer1);
            printf("\nSniffing Messenger Messages\n"); 
        }
		  }    

	}
      
	}
	return 0;

}


void /*LPSTR*/ ExtractPacket(char *cMsnPacket)
{   int c=0;
    char szC[255];
    char* j =  new char[255];
    int i=strlen(cMsnPacket);
    do{
    c++;
    i--;
    }while(cMsnPacket[i]!='\n');    
    int a;
    for(a=0;a<c;a++) printf("%c",cMsnPacket[i+a]);
}  //lstrcpy(j,szC);
//return j;

    
    
       



