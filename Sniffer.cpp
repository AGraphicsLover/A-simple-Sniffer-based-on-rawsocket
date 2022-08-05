#include<iostream>
#include<iomanip>
#include<arpa/inet.h>
#include<net/if.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<sys/ioctl.h>
#include<netinet/if_ether.h>
#include<string.h>
#include<sys/types.h>
using namespace std;

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;

typedef struct filter
{
    unsigned long sip;
    unsigned long dip;
    unsigned int protocol;    
} filter;

typedef struct ether_header_t{
    BYTE des_hw_addr[6];    //目的MAC地址
    BYTE src_hw_addr[6];    //源MAC地址
    WORD frametype;       //数据长度或类型
} ether_header_t;

typedef struct ip_header_t{
    BYTE hlen_ver;         //头部长度和版本信息
    BYTE tos;              //8位服务类型
    WORD total_len;        //16位总长度
    WORD id;             //16位标识符
    WORD flag;           //3位标志+13位片偏移
    BYTE ttl;             //8位生存时间
    BYTE protocol;        //8位上层协议号    
    WORD checksum;      //16位校验和
    DWORD src_ip;       //32位源IP地址
    DWORD des_ip;      //32位目的IP地址
} ip_header_t;

typedef struct arp_header_t{
    WORD hw_type;          //16位硬件类型
    WORD prot_type;         //16位协议类型
    BYTE hw_addr_len;       //8位硬件地址长度
    BYTE prot_addr_len;      //8位协议地址长度
    WORD flag;             //16位操作码
    BYTE send_hw_addr[6];   //源Ethernet网地址
    DWORD send_prot_addr;  //源IP地址
    BYTE des_hw_addr[6];    //目的Ethernet网地址
    DWORD des_prot_addr;   //目的IP地址
} arp_header_t;

typedef struct tcp_header_t{
    WORD src_port;          //源端口
    WORD des_port;          //目的端口
    DWORD seq;             //seq号
    DWORD ack;             //ack号
    BYTE len_res;            //头长度
    BYTE flag;               //标志字段 
    WORD window;           //窗口大小
    WORD checksum;         //校验和
    WORD urp;              //紧急指针 
} tcp_header_t;

typedef struct udp_header_t{
    WORD src_port;          //源端口
    WORD des_port;          //目的端口 
    WORD len;              //数据报总长度
    WORD checksum;        //校验和
} udp_header_t;

typedef struct icmp_header_t{
    BYTE type;              //8位类型     
    BYTE code;              //8位代码
    WORD checksum;         //16位校验和
    WORD id;               //16位标识符   
    WORD seq;              //16位序列号
} icmp_header_t;

typedef struct ip_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
} ip_packet_t;

typedef struct arp_packet_t{
    ether_header_t etherheader; 
    arp_header_t arpheader;
} arp_packet_t;

typedef arp_header_t rarp_header_t;
typedef arp_packet_t rarp_packet_t;

typedef struct tcp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    tcp_header_t tcpheader;
} tcp_packet_t;

typedef struct udp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    udp_header_t udpheader;
} udp_packet_t;

typedef struct icmp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    icmp_header_t icmpheader;
} icmp_packet_t;

class rawsocket
{
private:
	int sockfd;
public:
	rawsocket(const int protocol);
	~rawsocket(){};
	//set the promiscuous mode.
	bool dopromisc(char *nif);
	//capture packets.
	int receive(char *recvbuf,int buflen,struct sockaddr_in *from,int *addrlen);
};

rawsocket::rawsocket(const int protocol)
{
    sockfd=socket(PF_PACKET,SOCK_RAW,protocol);
    if(sockfd<0)
    {
	    perror("socket error: ");
    }
}

bool rawsocket::dopromisc(char*nif)
{
    struct ifreq ifr;              
    strcpy(ifr.ifr_name,nif);
    if((ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1))  
    {         
       	perror("ioctlread: ");  
	    return false;
    }	
    ifr.ifr_flags |= IFF_PROMISC; 
    if(ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1 )
    { 
     	perror("ioctlset: ");
	    return false;
    }
    return true;
}

int rawsocket::receive(char *recvbuf,int buflen, struct sockaddr_in *from,int *addrlen)
{
    int recvlen;
    recvlen=recvfrom(sockfd,recvbuf,buflen,0,(struct sockaddr *)from,(socklen_t *)addrlen);
    recvbuf[recvlen]='\0';
    for(int i = 0;i<recvlen;i++)
    {
    	cout<<hex<<((unsigned int)(recvbuf[i])&0xff)<<' ';
    }
    return recvlen;
}

class rawsocsniffer:public rawsocket
{
private:
	filter simfilter;
	const int max_packet_len = 2048;
public:
    char *packet;
	rawsocsniffer(int protocol):rawsocket(protocol)
    {
        packet = new char[max_packet_len];
        this->simfilter.protocol = 0;
        this->simfilter.sip=0;
        this->simfilter.dip = 0;
    }
	~rawsocsniffer(){};
	bool init(const char *NIC_name);
	void setfilter(filter myfilter);
	bool testbit(const unsigned int p, int k);
	void setbit(unsigned int &p,int k);
	void sniffer();
	void analyze();
	void ParseRARPPacket();
	void ParseARPPacket();
	void ParseIPPacket();
	void ParseTCPPacket();
	void ParseUDPPacket();
	void ParseICMPPacket();
	void print_hw_addr(const unsigned char *ptr);
	void print_ip_addr(const unsigned long ip);
};

bool rawsocsniffer::init(const char *NIC_name)
{
    char * nic_name;
    strcpy(nic_name, NIC_name);
    return (dopromisc(nic_name));
}

void rawsocsniffer::setfilter(filter myfilter)
{
    simfilter.protocol=myfilter.protocol;
    simfilter.sip=myfilter.sip;
    simfilter.dip=myfilter.dip;
}

bool rawsocsniffer::testbit(const unsigned int p,int k)
{
    if((p>>(k-1))&0x0001)
	    return true;
    else
	    return false;
}

void rawsocsniffer::setbit(unsigned int &p,int k)
{
    p=(p)|((0x0001)<<(k-1));
}

void rawsocsniffer::sniffer()
{
    struct sockaddr_in from;
    int sockaddr_len=sizeof(struct sockaddr_in);
    int recvlen=0;
    while(1)
    {
    	recvlen=receive(packet,max_packet_len,&from,&sockaddr_len);
    	if(recvlen>0)
    	{
	        analyze();
    	}
   	    else
    	{
	        continue;
    	}
    }	 
}

void rawsocsniffer::analyze()
{
    ether_header_t *etherpacket=(ether_header_t *)packet;
    if(simfilter.protocol==0)
	    simfilter.protocol=0xffffffff;
    switch (ntohs(etherpacket->frametype)&0xffff)
    {
	case 0x0800:
	    if(((simfilter.protocol)>>1))
	    {
	    	cout<<"\n\n/*---------------ip packet--------------------*/"<<endl;
	    	ParseIPPacket();
	    }
	    break;
	case 0x0806:
	    if(testbit(simfilter.protocol,1))
	    {
	    	cout<<"\n\n/*--------------arp packet--------------------*/"<<endl;
	    	ParseARPPacket();
	    }
	    break;
	case 0x0835:
	    if(testbit(simfilter.protocol,5))
	    {
		    cout<<"\n\n/*--------------RARP packet--------------------*/"<<endl;
		    ParseRARPPacket();
	    }
	    break;
	default:
	    cout<<"\n\n/*--------------Unknown packet----------------*/"<<endl;
	    cout<<"Unknown ethernet frametype!"<<endl;
	    break;
    }
}

void rawsocsniffer::print_hw_addr(const unsigned char *ptr)
{
	cout<<"hw_addr";
	for(int i = 0;i<6;i++)
	{
		cout<<':'<<hex<<((unsigned int)(ptr[i])&0xff);
	}
	cout<<'\n';
}

void rawsocsniffer::print_ip_addr(const unsigned long ipn)
{
	unsigned long ip = ntohl(ipn);
	unsigned short ip0 = ip&0xff;
	unsigned short ip1 = (ip>>8)&0xff;
	unsigned short ip2 = (ip>>16)&0xff;
	unsigned short ip3 = (ip>>24)&0xff;
	cout<<"ip_addr:"<<dec<<ip3<<'.'<<ip2<<'.'<<ip1<<'.'<<ip0<<endl;
}

void rawsocsniffer::ParseARPPacket()
{
    arp_packet_t *arppacket=(arp_packet_t *)packet;
    cout<<"MAC TO:";
    print_hw_addr(arppacket->arpheader.des_hw_addr);
    cout<<"ip to:";
    print_ip_addr(arppacket->arpheader.des_prot_addr);
    cout<<endl;
    cout<<"MAC FROM:";
    print_hw_addr(arppacket->arpheader.send_hw_addr);
    cout<<"ip from:";
    print_ip_addr(arppacket->arpheader.send_prot_addr);
    
}

void rawsocsniffer::ParseRARPPacket()
{
    rarp_packet_t *rarppacket = (rarp_packet_t*)packet;
    print_hw_addr(rarppacket->arpheader.des_hw_addr);
    print_hw_addr(rarppacket->arpheader.send_hw_addr);
    cout<<endl;
    print_ip_addr(rarppacket->arpheader.send_prot_addr);
    print_ip_addr(rarppacket->arpheader.des_prot_addr);
}

void rawsocsniffer::ParseIPPacket()
{
    ip_packet_t *ippacket=(ip_packet_t *)packet; 
    cout<<"ipheader.protocol: "<<dec<<((unsigned int)(ippacket->ipheader.protocol)&0xff)<<endl;
    if(simfilter.sip!=0)
    {
	    if(simfilter.sip!=(ippacket->ipheader.src_ip))
	        return;
    }
    if(simfilter.dip!=0)
    {
	    if(simfilter.dip!=(ippacket->ipheader.des_ip))
	        return;
    }
    switch ((unsigned int)(ippacket->ipheader.protocol)&0xff)
    {
	case 1:
	    if(testbit(simfilter.protocol,4))
	    {
	    	cout<<"Received an ICMP packet"<<endl;
	    	ParseICMPPacket();
	    }
	    break;
	case 6:
	    if(testbit(simfilter.protocol,2))
	    {
	    	cout<<"Received an TCP packet"<<endl;
	    	ParseTCPPacket();
	    }
	    break;
	case 17:
	    if(testbit(simfilter.protocol,3))
	    {
	    	cout<<"Received an UDP packet"<<endl;
	    	ParseUDPPacket();
	    }
	    break;
/*省略针对其他协议的分析*/
    }
}

void rawsocsniffer::ParseICMPPacket()
{
    icmp_packet_t *icmppacket=(icmp_packet_t *)packet;
    cout<<setw(20)<<"MAC address: from ";
    print_hw_addr(icmppacket->etherheader.src_hw_addr);
    cout<<"to ";
    print_hw_addr(icmppacket->etherheader.des_hw_addr);
    cout<<endl<<setw(20)<<"IP address: from ";
    print_ip_addr(icmppacket->ipheader.src_ip);
    cout<<"to ";
    print_ip_addr(icmppacket->ipheader.des_ip);
    cout<<endl;
    cout<<setw(12)<<"icmp type: "<<int(icmppacket->icmpheader.type)<<" icmp code: "<<int(icmppacket->icmpheader.code)<<endl;
    cout<<setw(12)<<"icmp id: "<<ntohs(icmppacket->icmpheader.id)<<" icmp seq: "<<ntohs(icmppacket->icmpheader.seq)<<endl;
}

void rawsocsniffer::ParseTCPPacket()
{
    tcp_packet_t *tcppacket=(tcp_packet_t *)packet;
    cout<<setw(20)<<"MAC address: from ";
    print_hw_addr(tcppacket->etherheader.src_hw_addr);
    cout<<"to ";
    print_hw_addr(tcppacket->etherheader.des_hw_addr);
    cout<<endl<<setw(20)<<"IP address: from ";
    print_ip_addr(tcppacket->ipheader.src_ip);
    cout<<"to ";
    print_ip_addr(tcppacket->ipheader.des_ip);
    cout<<endl;
    cout<<setw(10)<<"srcport: "<<ntohs(tcppacket->tcpheader.src_port)<<" desport: "<<ntohs(tcppacket->tcpheader.des_port)<<endl;
    cout<<"seq: "<<ntohl(tcppacket->tcpheader.seq)<<" ack: "<<ntohl(tcppacket->tcpheader.ack)<<endl;
}

void rawsocsniffer::ParseUDPPacket()
{
    udp_packet_t *udppacket=(udp_packet_t *)packet;
    cout<<setw(20)<<"MAC address: from ";
    print_hw_addr(udppacket->etherheader.src_hw_addr);
    cout<<"to ";
    print_hw_addr(udppacket->etherheader.des_hw_addr);
    cout<<endl<<setw(20)<<"IP address: from ";
    print_ip_addr(udppacket->ipheader.src_ip);
    cout<<"to ";
    print_ip_addr(udppacket->ipheader.des_ip);
    cout<<endl;
    cout<<setw(10)<<"srcport: "<<ntohs(udppacket->udpheader.src_port)<<" desport: "<<ntohs(udppacket->udpheader.des_port)\
	<<" length:"<<ntohs(udppacket->udpheader.len)<<endl;
}

int main()
{
	int protocol = htons(ETH_P_ALL);
	rawsocsniffer sniffer = rawsocsniffer(protocol);
	string s;
	cin>>s;
	const char * nic_name = s.c_str();
	cerr<<nic_name;
	if(sniffer.init(nic_name))
		cerr<<" Network Interface Card initialized successfully!"<<endl;
	else
	{
		cerr<<"initialized error!!!!"<<endl;
		return 1;
	}
	sniffer.sniffer();
	return 0;
}