#pragma once
#include "define.h"
#include "Global.h"
#include "PcapManager.h"
#include "DataLoader.h"
#include "SharedContext.h"
enum DESTINATION
{
	DST_SVR,
	DST_CLI
};

class PacketDetect
{
public:
	PacketDetect(SharedContext &, int mode,bool bXDP);
	~PacketDetect();

	void packet_detect(const int ThreadID, const pcap_t *adhandle);
	void packet_Reset(const TcpHeader *pTcp, const u_char *pktdata, const pcap_t *adhandle);

	bool packet_AnalyzeInline(unsigned char *pkt_data, int len, nfq_data *nfa);
	void packet_Reset(const TcpHeader *pTcp, const u_char *pktdata);
	void packet_ResetInline(unsigned char *pkt_data, int len, nfq_data *nfa, const pcap_t *adhandle);

	void UpdateXdpBlcaklist(uint32_t srcip);
	void RemoveXdpBlcaklist(uint32_t srcip);

	void RemoveXdpWhitelist(uint32_t srcip);
	void UpdateXdpWhitelist(uint32_t srcip);



	void ResetXdpBlacklist();
	void ResetAccumulateStat()
	{
		std::unique_lock<std::shared_mutex> lock(m_shared_statsMutex);
		m_accumulate_stat.clear();
	}
	private:
	void _packet_DstSetting(DESTINATION eTarget);
	std::vector<thread> ThreadPool;
	set<uint32_t> local_blacklist;
	set<uint32_t> local_whitelist;

	
	/*std::vector<map<uint32_t, pair<Packet, int>>>& m_pWorker_queues;
	concurrency::concurrent_queue<uint32_t>& m_pBlacklist_queue;*/
	
	// const NetworkConfig& m_config;
	SharedContext &g_ctx; // 참조
	bool bRunnig{true};
	int m_mode;
	bool XDP{false};

	shared_mutex m_shared_statsMutex;
	mutex m_statsMutex;
	std::chrono::steady_clock::time_point m_last_check_time;
	unordered_map<uint32_t, PacketCount> m_accumulate_stat;
	std::unordered_map<uint64_t, int> m_mac_stat;
	std::set<uint32_t> m_whitelist;
	std::set<uint32_t> m_greylist;
};
