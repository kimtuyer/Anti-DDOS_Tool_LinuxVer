#include "PacketCapture.h"
#include "PacketDetect.h"
#include <cstdlib>

// #include "Global.h"

PacketCapture::PacketCapture(SharedContext &context, PacketDetect *pDetect, int mode) : ctx(context), m_mode(mode), m_pDetect(pDetect)
{
}
PacketCapture::~PacketCapture()
{
}

void PacketCapture::packet_capture(const pcap_pkthdr *header, const u_char *pkt_data)
{
	// CaptureContext* ctx = (CaptureContext*)param;
	EtherHeader *pEther = (EtherHeader *)pkt_data;
	IpHeader *pIpHeader = (IpHeader *)(pkt_data + sizeof(EtherHeader));

	uint32_t src_ip = *(uint32_t *)(pIpHeader->srcIp);
	// uint32_t ip{};
	uint64_t srcMacKey = MacToUint64(pEther->srcMac); // MAC -> uint64 변환

	int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
	TcpHeader *pTcp = (TcpHeader *)(pkt_data + sizeof(EtherHeader) + ipHeaderLen);

	if (ctx.g_syn_count < 5000)
	{
		// ACK 비율 확인
		if (ctx.g_ack_count < (ctx.g_syn_count * 0.1))
		{
			// SYN은 3000개인데 ACK가 300개도 안 옴 -> 공격 의심!
			// First Packet Drop 모드 ON
			ctx.g_emergency_mode = true;
		}
	}
	////이미 차단된 계정이 다시 접속을 시도할경우? 도 생각해서 차단해야함!
	// if (local_blacklist.contains(src_ip))
	//{
	//	//차단된 계정이 다시 접속을 시도해 연결 수립하는 ack 패킷은 다시 캡쳐 후 탐지해서 차단!
	//	//syn 패킷 공격을 할 경우도 고려해야함.
	//	if (pTcp->flags != 0x010)
	//	{
	//		if (!(pTcp->flags & 0x02))
	//		{

	//		}
	//		else
	//			return;
	//	}
	//}
	// auto now = std::chrono::steady_clock::now();

	// while (ctx.blacklist_queue.try_pop(ip))
	//{
	//	auto last_check_time = std::chrono::steady_clock::now();

	//	//1초이상 경과시 다음에 처리
	//	if (chrono::duration_cast<std::chrono::seconds>(now - last_check_time).count() >= 1)
	//	{
	//		break;
	//	}

	//	local_blacklist.insert(ip);
	//}

	if (pEther->type != 0x0008)
		return;

	if (pIpHeader->protocol != 6)
		return;

	if (pTcp->flags == 0x004) // RST 패킷, 즉 툴이 보내는 종료패킷은 제외!
		return;

	// if (pIpHeader->id == 0x3412)
	//	return; //툴 자신이 생성해 보낸 패킷은 제외!

	// 일단 내 포트폴리오 게임서버 포트로 설정 ,클라는 각각 당연히 포트가 다를것.
	if (ntohs(pTcp->srcPort) != ctx.config.server_port && ntohs(pTcp->dstPort) != ctx.config.server_port) // ntohs(pTcp->srcPort) != 25000 &&
		return;

	Packet data(const_cast<pcap_pkthdr *>(header), const_cast<u_char *>(pkt_data));

	int worker_index = src_ip % NUM_WORKER_THREADS;
	auto &target_worker = ctx.workers[worker_index];

	int syn_count = (pTcp->flags & 0x02) ? 1 : 0;
	int ack_count = (pTcp->flags == 0x010) ? 1 : 0;

	if (syn_count == 1)
		ctx.g_syn_count++;
	if (ack_count == 1)
		ctx.g_ack_count++;
	{
		std::lock_guard<mutex> lock(target_worker->q_mutex);
		if (target_worker->packetlist.contains(src_ip))
		{
			target_worker->packetlist[src_ip].second.TotalCount++;

			// 클라->서버 ,서버->클라, 클라->서버 ACK 보내는 마지막 패킷 캡쳐
			if (ack_count == 1) // Flags 비트 값이 0x010 (ACK)일 경우에만 패킷데이터 업데이트!
			{
				target_worker->packetlist[src_ip].first = data;
			}
			else if (syn_count == 1) // SYN Flag , SYN Flood 고려
			{
				target_worker->packetlist[src_ip].second.syn_count++;
			}
		}
		else
		{
			target_worker->packetlist.insert({src_ip, {data, PacketCount(1, syn_count)}});
		}

		// 2. ★ MAC 기반 카운팅 추가 ★
		target_worker->mac_stat[srcMacKey]++;
	}
	target_worker->q_cv.notify_one();
}

void PacketCapture::packet_handler(u_char *user, const pcap_pkthdr *header, const u_char *pkt_data)
{
	// user로 들어온 포인터를 PacketMonitor 클래스 포인터로 캐스팅
	PacketCapture *self = reinterpret_cast<PacketCapture *>(user);

	// 실제 멤버 함수 호출
	self->packet_capture(header, pkt_data);
}

void PacketCapture::Run()
{

#ifdef __XDP_GLOBALMAP__
	// 1. PPS 리셋 전용 스레드 추가
	thread timerThread([this]()
					   {
        uint32_t key = 0;
        uint64_t zero = 0;
        while (true) {
            this_thread::sleep_for(chrono::seconds(1)); // 1초 대기
            // global_pps_map의 0번 인덱스를 0으로 초기화
			//uint64_t current_pps;
            //bpf_map_lookup_elem(ctx.m_xdp_map_fd, &key, &current_pps);
			//printf("Current PPS: %llu\n", current_pps);
            bpf_map_update_elem(ctx.m_xdp_map_fd, &key, &zero, BPF_ANY);
            
            // (선택사항) 현재 PPS 로그 출력해서 모니터링
        } });
	timerThread.detach(); // 메인 로직과 별개로 계속 돌아가게 함
#endif
#ifdef __NETFILTER__
	// iptables 설정
	SetupIptables(NUM_WORKER_THREADS, ctx.config.server_port);

	for (int i = 0; i < NUM_WORKER_THREADS; i++)
	{
		ThreadPool.push_back(thread(&PacketCapture::_RunNetfilter, this, i));
	}
	// 메인 스레드가 바로 종료되지 않도록 join 처리 (혹은 detach)
	for (auto &t : ThreadPool)
	{
		if (t.joinable())
			t.join();
	}

	//  종료 시 규칙 제거
	CleanupIptables();

#else
	pcap_loop(const_cast<pcap_t *>(PcapAdmin.GetHandle()), 0, packet_handler, (u_char *)this);
#endif
}

int PacketCapture::nfq_callback(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa, void *data)
{
	PacketCapture *self = reinterpret_cast<PacketCapture *>(data);

	// 패킷 ID 추출 (Verdict 내릴 때 필요)
	uint32_t id = 0;
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	if (ph)
		id = ntohl(ph->packet_id);

	// 패킷 실제 데이터 추출
	unsigned char *pkt_data;
	int len = nfq_get_payload(nfa, &pkt_data);

	self->_packet_AddSumCnt(pkt_data);

	int verdict = self->m_pDetect->packet_AnalyzeInline(pkt_data, len, nfa);

	if (verdict)
	{
		// 공격이면 DROP!
		IpHeader *pIpHeader = (IpHeader *)pkt_data;
		uint32_t src_ip = *(uint32_t *)(pIpHeader->srcIp);

		// printf("[BLOCK] IP: %u, Verdict: DROP\n", src_ip);
		self->m_pDetect->packet_ResetInline(pkt_data, len, nfa, PcapAdmin.GetHandle());
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else
	{
		// 정상이면 ACCEPT!
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

void PacketCapture::_RunNetfilter(int queue_num)
{

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	// 1. NFQUEUE 핸들 열기
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		return;
	}

	// 2. 기존 핸들 바인딩 해제 및 IPv4 바인딩
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
	}
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		return;
	}

	// 3. 큐 생성 (큐 번호 0번, 아까 iptables에서 설정한 번호)
	// nfq_callback은 정적 함수여야 하므로 'this'를 넘겨서 멤버 함수에 접근합니다.
	qh = nfq_create_queue(h, queue_num, &nfq_callback, (void *)this);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		return;
	}
	else
	{
		// 큐의 길이를 기존 1024에서 10,000으로 대폭 확대
		if (nfq_set_queue_maxlen(qh, 10000) < 0)
		{
			fprintf(stderr, "can't set queue maxlen\n");
		}
	}

	// 4. 패킷 카피 모드 설정 (패킷 전체 내용을 유저 모드로 가져옴)
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		return;
	}

	// 5. 소켓 파일 디스크립터 가져오기 및 루프
	fd = nfq_fd(h);

	while (ctx.g_bRunning)
	{ // 종료 플래그 확인

		rv = recv(fd, buf, sizeof(buf), 0);
		if (rv >= 0)
		{
			if (nfq_handle_packet(h, buf, rv) < 0)
			{
				// nfq_handle_packet 내부 에러(주로 오버플로우) 시 계속 진행
				continue;
			}
		}
		else
		{
			// 에러 처리 세분화
			if (errno == EINTR)
			{
				continue;
			}
			if (errno == ENOBUFS)
			{
				// 핵심: 큐가 꽉 찼을 때는 break 하지 않고 경고만 찍고 계속 진행
				fprintf(stderr, "[Warn] NFQUEUE Buffer Overflow (ENOBUFS)\n");
				continue;
			}

			// 정말 심각한 에러(EBADF 등)일 때만 종료
			fprintf(stderr, "[Critical] Socket error: %s\n", strerror(errno));
			break;
		}
		// try
		// {
		// 	rv = recv(fd, buf, sizeof(buf), 0);
		// 	if (rv >= 0)
		// 	{
		// 		// 패킷 처리 중 발생하는 내부 에러가 루프를 깨지 않도록 보호
		// 		if (nfq_handle_packet(h, buf, rv) < 0)
		// 		{
		// 			// 큐 오버플로우 등으로 인한 에러 발생 시 로그만 남기고 계속 진행
		// 			fprintf(stderr, "[Warn] nfq_handle_packet error\n");
		// 			continue;
		// 		}
		// 	}
		// 	else if (rv < 0 && errno == EINTR)
		// 	{
		// 		continue; // 시그널에 의한 중단은 무시
		// 	}
		// 	else if (errno == ENOBUFS)
		// 	{
		// 		// 👈 핵심: 큐가 꽉 찼을 때는 break 하지 않고 경고만 찍고 계속 진행
		// 		// fprintf(stderr, "[Warn] NFQUEUE Buffer Overflow (ENOBUFS)\n");
		// 		continue;

		// 	}
		// 	else
		// 	{

		// 	}
		// }
		// catch (...)
		// {
		// 	// 모든 예기치 못한 예외 상황에서 스레드가 죽지 않도록 방어
		// 	continue;
		// }
	}

	// 정리
	nfq_destroy_queue(qh);
	nfq_close(h);
}

void PacketCapture::SetupIptables(int num_queues, int port)
{
	// 1. 기존 규칙 초기화 (안전을 위해 해당 포트 관련 규칙만 삭제하거나 전체 초기화)
	// sudo iptables -D INPUT -p tcp --dport 25000 -j NFQUEUE ... (기존 규칙이 있다면)

	// 2. NFQUEUE 규칙 추가 (0번부터 num_queues-1번까지 부하 분산)
	std::string cmd = "sudo iptables -A INPUT -p tcp --dport " + std::to_string(port) +
					  " -j NFQUEUE --queue-balance 0:" + std::to_string(num_queues - 1);

	printf("[System] Setting up iptables: %s\n", cmd.c_str());
	if (system(cmd.c_str()) != 0)
	{
		fprintf(stderr, "Failed to set iptables rule. Check sudo privileges.\n");
	}
}

void PacketCapture::CleanupIptables()
{
	// 모든 규칙 초기화 (flush) - 주의: 다른 규칙이 있다면 -D 옵션으로 특정 규칙만 지우는 것이 좋습니다.
	printf("[System] Cleaning up iptables rules...\n");
	system("sudo iptables -F");
}

void PacketCapture::_packet_AddSumCnt(unsigned char *pkt_data)
{
	IpHeader *pIpHeader = (IpHeader *)pkt_data;
	int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
	TcpHeader *pTcp = (TcpHeader *)(pkt_data + ipHeaderLen);

	int syn_count = (pTcp->flags & 0x02) ? 1 : 0;
	int ack_count = (pTcp->flags == 0x010) ? 1 : 0;

	if (syn_count == 1)
		ctx.g_syn_count++;
	if (ack_count == 1)
		ctx.g_ack_count++;
}

void PacketCapture::_RunPcap()
{
}
