#pragma once
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap.h>
#include <thread>
#include <vector>
//#include <concurrent_queue.h>
#include<map>
#include<unordered_map>
#include<string>
#include<chrono>
#include<mutex>
#include<shared_mutex>
#include<queue>
#include<set>
//#include <tchar.h>
#include <time.h>
#include<iostream>



#include <atomic> // 리눅스에서 필수
#include <condition_variable>  // 리눅스에서 필수

#define __VER2__
#define __OOP__
#define __DATA_LOADING__

#define __LINUX__
#define __NETFILTER__
#define __XDP__
#define __XDP_GLOBALMAP__
#define __XDP_WHITELIST__
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h> // NF_ACCEPT, NF_DROP 정의
#include <netinet/in.h>
#include <netinet/ether.h>     // Ethernet 헤더 (struct ethhdr)
#include <netinet/ip.h>        // IP 헤더 (struct iphdr)
#include <netinet/tcp.h>       // TCP 헤더 (struct tcphdr)
#include <arpa/inet.h>         // inet_ntoa 등 주소 변환 함수
#include <net/if.h>            // 네트워크 인터페이스 관련
using namespace std;

const int NUM_WORKER_THREADS = 4;
const int TIME_WAIT = 1000;

enum eMode
{
	MODE_PCAP=1,
	MODE_NETFILTER
};


#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6];
	unsigned char srcMac[6];
	unsigned short type;
} EtherHeader;

typedef struct IpHeader {
	unsigned char verIhl;
	unsigned char tos;
	unsigned short length;
	unsigned short id;
	unsigned short fragOffset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char srcIp[4];
	unsigned char dstIp[4];
} IpHeader;

typedef struct TcpHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned int seq;
	unsigned int ack;
	unsigned char data;
	unsigned char flags;
	unsigned short windowSize;
	unsigned short checksum;
	unsigned short urgent;
} TcpHeader;

typedef struct UdpHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned short length;
	unsigned short checksum;
} UdpHeader;

typedef struct PseudoHeader {
	unsigned int srcIp;
	unsigned int dstIp;
	unsigned char zero;
	unsigned char protocol;
	unsigned short length;
} PseudoHeader;

 struct Packet {

	struct pcap_pkthdr m_pheader {};
	vector<u_char> m_pkt_data;
	Packet()
	{

	}

	Packet(struct pcap_pkthdr* header, u_char* pkt_data)
	{
		if (header != nullptr && pkt_data != nullptr) {
			// 헤더 복사 (구조체끼리 대입하면 값 복사됨)
			m_pheader = *header;

			// [핵심] 데이터 깊은 복사 (Deep Copy)
			// vector의 assign 함수: 시작 포인터부터 길이만큼 복사해서 내 메모리에 저장
			m_pkt_data.assign(pkt_data, pkt_data + header->caplen);
		}
		//m_pheader = header;
		//m_pkt_data = pkt_data;
	}

};
struct PacketCount
{
	PacketCount()
		:TotalCount(0), syn_count(0)
	{

	}
	PacketCount(int total, int syncount)
		:TotalCount(total),syn_count(syncount)
	{

	}
	int TotalCount{}; //flag 비트 관계없는 전체 패킷 개수
	int syn_count{}; //syn flag인 패킷 개수

};

// 생산자(Producer)가 패킷 처리에 필요한 모든 '상태'를 담는 가방
struct CaptureContext {
	// 로컬 블랙리스트 (락 필요 없음, 생산자만 봄)
	set<uint32_t> local_blacklist;
	// 워커들에게서 차단 요청을 받을 피드백 큐 (스레드 안전)
	//concurrency::concurrent_queue<uint32_t> feedback_queue;
};
#pragma pack(pop)