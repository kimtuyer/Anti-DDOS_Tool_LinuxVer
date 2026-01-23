#include "PacketDetect.h"
#include <cinttypes>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
// #include "Global.h"

PacketDetect::PacketDetect(SharedContext &context, int mode, bool bXDP) : g_ctx(context), m_mode(mode), XDP(bXDP)
{
    if (mode == eMode::MODE_PCAP)
    {
        for (int i = 0; i < NUM_WORKER_THREADS; i++)
            ThreadPool.push_back(thread(&PacketDetect::packet_detect, this, i, PcapAdmin.GetHandle()));
    }
}

PacketDetect::~PacketDetect()
{

    g_ctx.g_bRunning = false;
    for (auto &t : ThreadPool)
    {
        // t 자체가 유효하고 join 가능한 상태인지 확인
        if (t.joinable())
        {
            try
            {
                t.join();
            }
            catch (...)
            {
                // join 과정에서의 예외 방지
            }
        }
    }
    // for (int i = 0; i < NUM_WORKER_THREADS; i++)
    //     if (ThreadPool[i].joinable())
    //         ThreadPool[i].join();
}

void PacketDetect::packet_detect(const int ThreadID, const pcap_t *adhandle)
{
    auto last_check_time = std::chrono::steady_clock::now();

    // int size = 500;
    unordered_map<uint32_t, pair<Packet, PacketCount>> local_IPList;
    unordered_map<uint32_t, pair<Packet, PacketCount>> accomulate_stat;

    auto &my_ctx = g_ctx.workers[ThreadID];

    while (bRunnig)
    {
        {
            std::unique_lock<std::mutex> lock(my_ctx->q_mutex);

            // (조건: 내 큐가 비어있지 않거나, 종료 신호가 왔을 때)
            my_ctx->q_cv.wait(lock, [&]
                              { return !my_ctx->packetlist.empty() || !bRunnig; });

            if (!bRunnig)
                break;

            // 1초 주기로 ip별 패킷 카운트 수 초기화
            auto now = std::chrono::steady_clock::now();
            if (chrono::duration_cast<std::chrono::seconds>(now - last_check_time).count() >= 1)
            {
                last_check_time = now;
                accomulate_stat.clear();
                my_ctx->mac_stat.clear();
            }
            // printf("--- 1초 경과: 카운트 리셋 ---\n");

            local_IPList.swap(my_ctx->packetlist);

            lock.unlock(); // 락 해제
        }

        for (auto [ip, data] : local_IPList)
        {
            accomulate_stat[ip].second.TotalCount += data.second.TotalCount;
            accomulate_stat[ip].second.syn_count += data.second.syn_count;

            auto packet = data.first;

            if (packet.m_pkt_data.empty())
                continue;

            accomulate_stat[ip].first = packet;

            u_char *raw_ptr = packet.m_pkt_data.data();

            // EtherHeader* pEther = (EtherHeader*)raw_ptr;
            IpHeader *pIpHeader = (IpHeader *)(raw_ptr + sizeof(EtherHeader));

            if (packet.m_pkt_data.size() < sizeof(EtherHeader) + 20)
            {
                continue; // 최소한의 IP 헤더 길이도 안 되면 패스
            }

            int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
            TcpHeader *pTcp =
                (TcpHeader *)(raw_ptr + sizeof(EtherHeader) + ipHeaderLen);

            printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
                   pIpHeader->srcIp[0], pIpHeader->srcIp[1],
                   pIpHeader->srcIp[2], pIpHeader->srcIp[3],
                   ntohs(pTcp->srcPort),
                   pIpHeader->dstIp[0], pIpHeader->dstIp[1],
                   pIpHeader->dstIp[2], pIpHeader->dstIp[3],
                   ntohs(pTcp->dstPort));

            int tcpHeaderSize = ((pTcp->data >> 4 & 0x0F) * 4);
            // char* pPayload = (char*)(raw_ptr + sizeof(EtherHeader) +
            // 	ipHeaderLen + tcpHeaderSize);

            int Segmentsize = ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize;
            printf("Segment size: %d(Frame length: %d)\n",
                   Segmentsize,
                   packet.m_pheader.len);

            if (g_ctx.g_emergency_mode)
            {
                // SYN 패킷일 경우에 확인
                if (!(pTcp->flags & 0x02))
                    continue;

                // 1. 이미 검증된 IP인가? (Whitelist / Established)
                if (my_ctx->whitelist.contains(ip))
                {
                    continue; // 통과
                }

                // 2. 재전송 대기 목록(Greylist)에 있는가?
                if (my_ctx->greylist.contains(ip))
                {

                    my_ctx->greylist.erase(ip);   // 대기 목록에서 제거
                    my_ctx->whitelist.insert(ip); // 정식 유저로 승격
                    continue;                     // 통과 (서버가 처리하게 둠)
                }

                // 3. 처음 보는 IP인가? -> First Drop 실행
                else
                {
                    // [서버 보호] 서버에게 RST를 보내서 백로그 비우기
                    printf("Packet Reset Try!");
                    packet_Reset(pTcp, raw_ptr, adhandle);

                    // [대기열 등록] "너 한 번만 더 보내봐. 그럼 믿어줄게"
                    my_ctx->greylist[ip] = std::chrono::steady_clock::now();
                    continue;
                }
            }
            else
            {
                // [검사 1] SYN Flood 감지 (우선순위 높음)
                // TCP 헤더의  SYN Flag 검사
                if (accomulate_stat[ip].second.syn_count > 10)
                {
                    // 만약 syn_count > 20 -> BLACKLIST
                    packet_Reset(pTcp, raw_ptr, adhandle);
                    // ctx.blacklist_queue.push(ip);
                    local_blacklist.insert(ip);
                    continue;
                }

                // 클라->서버 ,서버->클라, 클라->서버 ACK 보내는 마지막 패킷 캡쳐
                if (pTcp->flags == 0x010) // Flags 비트 값이 0x010 (ACK)일 경우에만 읽고 탐지
                {
                    // [검사 2] 이미 블랙리스트 등록된 ip 감지
                    if (local_blacklist.contains(ip))
                    {
                        packet_Reset(pTcp, raw_ptr, adhandle);
                        // ctx.blacklist_queue.push(ip);
                        local_blacklist.insert(ip);
                        continue;
                    }
                    // [검사 3] 과도한 트래픽(DDoS) 감지
                    // if (accomulate_stat[ip].second.TotalCount > 100)
                    {
                        printf("Packet Reset Try!");

                        packet_Reset(pTcp, raw_ptr, adhandle);
                        // ctx.blacklist_queue.push(ip);
                        local_blacklist.insert(ip);
                        continue;
                    }
                }
            }
        }
        local_IPList.clear();

        // [검사 4] MAC 기반 SYN Flood 탐지 (IP Spoofing 방어)
        // 주의: 실제 환경에선 Gateway MAC일 수 있으므로 임계값을 아주 높게 잡거나,
        // 내부망 테스트용임을 인지해야 함.
        for (auto const &[macKey, count] : my_ctx->mac_stat)
        {
            if (count > 500) // 예: 한 MAC에서 초당 500개 이상? 수상함
            {
                // 해당 MAC에서 들어오는 모든 패킷 차단 로직 필요
                // 하지만 IP가 계속 바뀌므로 blacklist_queue(IP)에 넣는 건 의미가 없음.
                // 여기서는 "경고"를 띄우거나, "글로벌 방어 모드"를 켜는 트리거로 써야 함.
                // printf("[Warning] MAC Flood Detected! MAC: %lx, Count: %d\n", macKey, count);
                printf("[Warning] MAC Flood Detected! MAC: %" PRIx64 ", Count: %d\n", macKey, count);

                // ★ 대응 전략:
                // IP가 위조되었으므로 특정 IP를 차단하는 건 불가능.
                // 따라서 잠시동안 "모든 SYN 패킷"에 대해 엄격한 검사(SYN Cookie 등)를 수행하거나
                // 현재 테스트 환경이라면 해당 MAC을 블랙리스트에 등록할 수 있음.
            }
        }
    }
}

void PacketDetect::packet_Reset(const TcpHeader *pTcp, const u_char *pktdata, const pcap_t *adhandle)
{
    EtherHeader *pEther = (EtherHeader *)pktdata;
    IpHeader *pSrcIpHeader = (IpHeader *)(pktdata + sizeof(EtherHeader));

    // 캡처한 IP 헤더에서 전체 길이를 가져와 TCP 페이로드 길이를 계산
    // int ipLen = ntohs(pSrcIpHeader->length);
    // int ipHeaderLen = (pSrcIpHeader->verIhl & 0x0F) * 4;
    // int tcpHeaderLen = ((pTcp->data & 0xF0) >> 4) * 4;
    int payloadLen = ntohs(pSrcIpHeader->length) - ((pSrcIpHeader->verIhl & 0x0F) * 4) - (((pTcp->data & 0xF0) >> 4) * 4);
    // int payloadLen = ipLen - ipHeaderLen - tcpHeaderLen;

    for (int i = 0; i < 1; i++)
    {

        unsigned char frameData[60] = {0}; // 최소 패킷 사이즈
        EtherHeader *pEtherHeader = (EtherHeader *)frameData;
        IpHeader *pIpHeader = (IpHeader *)(frameData + sizeof(EtherHeader));
        TcpHeader *pTcpHeader = (TcpHeader *)(frameData + sizeof(EtherHeader) + 20);

        // 1. Ethernet 설정: 나(VM) -> 클라이언트(Windows)
        if (i == DESTINATION::DST_SVR) // 클라 ->서버
        {
            memcpy(pEtherHeader->srcMac, pEther->srcMac, 6);
            memcpy(pEtherHeader->dstMac, g_ctx.config.gateway_mac, 6);
        }
        else if (i == DESTINATION::DST_CLI) // 서버->클라
        {
            memcpy(pEtherHeader->srcMac, g_ctx.config.gateway_mac, 6); // 내 리눅스 MAC
            memcpy(pEtherHeader->dstMac, pEther->srcMac, 6);           // 캡처된 패킷의 소스(클라) MAC
        }
        pEtherHeader->type = htons(0x0800);

        // 2. IP 설정: 서버 -> 클라이언트
        pIpHeader->verIhl = 0x45;
        pIpHeader->length = htons(40);
        pIpHeader->protocol = 6;
        pIpHeader->ttl = 128;

        if (i == DESTINATION::DST_SVR) // 클라 ->서버
        {
            memcpy(pIpHeader->srcIp, pSrcIpHeader->srcIp, 4);
            memcpy(pIpHeader->dstIp, &g_ctx.config.server_ip_addr, 4);
        }
        else if (i == DESTINATION::DST_CLI)
        {

            memcpy(pIpHeader->srcIp, &g_ctx.config.server_ip_addr, 4); // 서버 IP (가짜 출발지)
            memcpy(pIpHeader->dstIp, pSrcIpHeader->srcIp, 4);          // 클라이언트 IP
        }
        pIpHeader->checksum = CalcChecksumIp(pIpHeader);

        pTcpHeader->data = 0x50;
        pTcpHeader->flags = 0x04; // RST
        pTcpHeader->windowSize = 0;
        pTcpHeader->checksum = CalcChecksumTcp(pIpHeader, pTcpHeader);
        // 3. TCP 설정 (가장 중요)
        if (i == DESTINATION::DST_SVR) // 클라 ->서버
        {
            pTcpHeader->srcPort = pTcp->srcPort;
            pTcpHeader->dstPort = htons(g_ctx.config.server_port);

            uint32_t baseSeq = ntohl(pTcp->seq) + payloadLen;

            // uint32_t s_nextSeq = ntohl(pTcp->seq) + payloadLen;
            // pTcpHeader->seq = htonl(s_nextSeq);
            pTcpHeader->ack = pTcp->ack; // 기존 ACK 유지
            // pTcpHeader->seq = pTcp->seq;
            for (int burst = 0; burst < 3; burst++)
            {
                pTcpHeader->seq = htonl(baseSeq + (burst)); // 100바이트 간격으로 타격
                pcap_sendpacket(const_cast<pcap_t *>(adhandle), frameData, 54);
            }
        }
        else if (i == DESTINATION::DST_CLI)
        {

            pTcpHeader->srcPort = htons(g_ctx.config.server_port); // 서버 포트
            pTcpHeader->dstPort = pTcp->srcPort;                   // 클라이언트 포트
            // 캡처한 패킷의 ACK를 나의 SEQ로 사용 (상대방이 기다리는 번호)
            pTcpHeader->seq = pTcp->ack;
            pTcpHeader->ack = 0;

            // 4. 전송
            pcap_sendpacket(const_cast<pcap_t *>(adhandle), frameData, 54);
        }
    }
    //     EtherHeader *pEther = (EtherHeader *)pktdata;
    //     IpHeader *pSrcIpHeader = (IpHeader *)(pktdata + sizeof(EtherHeader));

    //     unsigned char frameData[1514] = {0};
    //     IpHeader *pIpHeader = (IpHeader *)(frameData + sizeof(EtherHeader));
    //     int ipHeaderLen = 20;

    //     TcpHeader *pTcpHeader =
    //         (TcpHeader *)(frameData + sizeof(EtherHeader) + ipHeaderLen);
    //     EtherHeader *pEtherHeader = (EtherHeader *)frameData;
    // #ifdef __DATA_LOADING__

    //     // MAC 주소 설정
    //     memcpy(pEtherHeader->srcMac, pEther->srcMac, 6);           // 패킷에 담긴 클라 mac 주소
    //     memcpy(pEtherHeader->dstMac, g_ctx.config.gateway_mac, 6); // 전송할 서버 mac 주소

    //     // IP 설정
    //     // m_config.server_ip_addr은 이미 Network Order로 변환되어 있으므로 그대로 복사
    //     memcpy(pIpHeader->dstIp, &g_ctx.config.server_ip_addr, 4);
    //     memcpy(pIpHeader->srcIp, pSrcIpHeader->srcIp, 4);

    //     // Port 설정
    //     pTcpHeader->dstPort = htons(g_ctx.config.server_port);
    // #else

    //     int msgSize = 0;
    //     pEtherHeader->dstMac[0] = 0x00;
    //     pEtherHeader->dstMac[1] = 0x0C;
    //     pEtherHeader->dstMac[2] = 0x29;
    //     pEtherHeader->dstMac[3] = 0x72;
    //     pEtherHeader->dstMac[4] = 0x01;
    //     pEtherHeader->dstMac[5] = 0x51;

    //     pEtherHeader->srcMac[0] = 0x00;
    //     pEtherHeader->srcMac[1] = 0x50;
    //     pEtherHeader->srcMac[2] = 0x56;
    //     pEtherHeader->srcMac[3] = 0xC0;
    //     pEtherHeader->srcMac[4] = 0x00;
    //     pEtherHeader->srcMac[5] = 0x01;
    // #endif // __DATA_LOADING__

    //     pEtherHeader->type = htons(0x0800);

    //     // IpHeader* pIpHeader = (IpHeader*)(frameData + sizeof(EtherHeader));
    //     pIpHeader->verIhl = 0x45;
    //     pIpHeader->tos = 0x00;
    //     pIpHeader->length = htons(40);
    //     pIpHeader->id = 0x3412;
    //     pIpHeader->fragOffset = htons(0x4000); // DF
    //     pIpHeader->ttl = 0xFF;
    //     pIpHeader->protocol = 6; // TCP
    //     pIpHeader->checksum = 0x0000;

    // #ifdef __DATA_LOADING__
    // #else
    //     pIpHeader->srcIp[0] = 192;
    //     pIpHeader->srcIp[1] = 168;
    //     pIpHeader->srcIp[2] = 41;
    //     pIpHeader->srcIp[3] = 1;

    //     pIpHeader->dstIp[0] = 192;
    //     pIpHeader->dstIp[1] = 168;
    //     pIpHeader->dstIp[2] = 41;
    //     pIpHeader->dstIp[3] = 128;
    //     pTcpHeader->dstPort = htons(25000);
    // #endif

    //     pTcpHeader->srcPort = htons(ntohs(pTcp->srcPort)); // 반드시 일치
    //     pTcpHeader->seq = (pTcp->seq);                     // 반드시 일치 , pTcp->seq 값은 이미 Net-order 순서이므로 변환없이 그대로 복사
    //     pTcpHeader->ack = 0;
    //     pTcpHeader->data = 0x50;
    //     pTcpHeader->flags = 0x04; // RST
    //     pTcpHeader->windowSize = 0;
    //     pTcpHeader->checksum = 0x0000;
    //     pTcpHeader->urgent = 0;

    //     pIpHeader->checksum = CalcChecksumIp(pIpHeader);
    //     pTcpHeader->checksum = CalcChecksumTcp(pIpHeader, pTcpHeader);

    //     /* Send down the packet */
    //     if (pcap_sendpacket(const_cast<pcap_t *>(adhandle), // Adapter
    //                         frameData,                      // buffer with the packet
    //                         sizeof(EtherHeader) + sizeof(IpHeader) + sizeof(TcpHeader)) != 0)
    //     {
    //         fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(const_cast<pcap_t *>(adhandle)));
    //     }
}

bool PacketDetect::packet_AnalyzeInline(unsigned char *pkt_data, int len, nfq_data *nfa)
{

    if (!pkt_data || len < sizeof(IpHeader))
    {
        printf("Packet Length IP > Short!\n");
        return false; //
    }

    IpHeader *pIpHeader = (IpHeader *)pkt_data;

    uint32_t src_ip = *(uint32_t *)(pIpHeader->srcIp);

    int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;

    // hping3 테스트 공격 경험 인한 방어코드 추가
    int min_len = ipHeaderLen + sizeof(TcpHeader);
    if (min_len > len)
    {
        // 패킷이 너무 짧아 TCP 헤더를 읽을 수 없음
        printf("Packet Length  TCP >Short!\n");
        return true; // 안전하게 DROP
    }
    TcpHeader *pTcp = (TcpHeader *)(pkt_data + ipHeaderLen);

    // 공격시 ping 테스트하는 내 호스트 ip는 통과!
    // uint32_t my_host_ip = inet_addr("192.168.21.1");
    // if (src_ip == my_host_ip)
    // {
    //     printf("my_host_ip IP: %u\n", src_ip);

    //     return false;
    // }
    // SSH 패킷은 차단 대상에서 제외!
    if (ntohs(pTcp->dstPort) == 22 || ntohs(pTcp->srcPort) == 22)
    {
        return false; // 무조건 ACCEPT
    }
    // struct nfqnl_msg_packet_hw *mac = nfq_get_packet_hw(nfa);

    // if (ctx.g_syn_count < 5000)
    if (g_ctx.g_emergency_mode == false)
    {
        int syn_count = g_ctx.g_syn_count;
        int ack_count = g_ctx.g_ack_count;
        // ACK 비율 확인
        if (ack_count < (syn_count * 0.1))
        {
            // SYN은 3000개인데 ACK가 300개도 안 옴 -> 공격 의심!
            // First Packet Drop 모드 ON
            printf("Emergency mode On!\n");
            g_ctx.g_emergency_mode = true;
        }
    }
    //printf("1Entering Analyze for IP: %u\n", src_ip);

    // 2. 읽기 전용 검사 (Fast Reject/Accept)
    {
        std::shared_lock<std::shared_mutex> lock(m_shared_statsMutex);
        if (local_blacklist.contains(src_ip))
        {
            return true; // 즉시 드랍
        }
        if (local_whitelist.contains(src_ip))
        {
            return false; // 즉시 통과
        }
    }
    // 3. 통계 업데이트 및 판단
    // printf("Entering Analyze for IP: %u\n", src_ip);
    {
        std::unique_lock<std::shared_mutex> lock(m_shared_statsMutex);
        auto &stat = m_accumulate_stat[src_ip];
        stat.TotalCount++;
        if (pTcp->flags & 0x02)
            stat.syn_count++;

        // [A] 차단 조건 (DDoS 탐지)
        if (stat.syn_count > 10 || stat.TotalCount > 100)
        {
            // printf("blacklist insert: %u\n", src_ip);

            local_blacklist.insert(src_ip);
            UpdateXdpBlcaklist(src_ip);
            // 만약 화이트리스트에 있었다면 제거 (신뢰 상실)
            if (local_whitelist.erase(src_ip))
                RemoveXdpWhitelist(src_ip);
            return true;
        }
        // [B] 화이트리스트 승격 조건
        // 일정 시간 동안 정상 패킷을 꾸준히 보내온 IP는 화이트리스트로 승격
        // 예: 1초 동안 패킷이 20개 이상 들어왔지만, SYN Flood 조건에는 한참 못 미치는 경우
        if (local_whitelist.contains(src_ip) == false)
        {
            bool should_promote = false;

            // 1. 확실한 증거: TCP 연결이 성립된 패킷(ACK)인 경우 (SYN은 아님)
            if (pTcp->flags & 0x10) // ACK 플래그가 설정된 경우
            {
                should_promote = true;
            }
            // 2. 통계적 증거: 어느 정도 활동량이 증명된 경우
            else if (stat.TotalCount > 10)
            {
                should_promote = true;
            }
            if (should_promote)
            {
                local_whitelist.insert(src_ip);
                UpdateXdpWhitelist(src_ip); //커널 맵 동기화
                //printf("whitelist insert: %u\n", src_ip);
            }
        }
    }

    // [검사] Emergency Mode (First Drop / Greylist 로직)
    if (g_ctx.g_emergency_mode)
    {
        if (pTcp->flags & 0x02)
        { // SYN 패킷일 때만
            {
                std::shared_lock<std::shared_mutex> lock(m_shared_statsMutex);
                if (m_whitelist.contains(src_ip))
                {
                    lock.unlock();
                    // printf("whitelist Pass: %u\n", src_ip);
                    return false; // 허용
                }
            }

            {
                std::unique_lock<std::shared_mutex> lock(m_shared_statsMutex);
                // std::lock_guard<std::mutex> lock(m_statsMutex); // 통계 데이터 보호

                if (m_greylist.contains(src_ip))
                {

                    printf("whitelist insert: %u\n", src_ip);

                    m_greylist.erase(src_ip);
                    m_whitelist.insert(src_ip);
                    UpdateXdpWhitelist(src_ip);
                    return false; // 재전송 확인됨 -> 허용
                }
                else
                {
                    // First Drop: 기록만 하고 패킷은 버림
                    m_greylist.insert({src_ip});
                    // printf("greylist insert: %u\n", src_ip);

                    return true; // DROP
                }
            }
        }
    }

    return false; // 모든 검사 통과 -> ACCEPT
}

void PacketDetect::packet_ResetInline(unsigned char *pkt_data, int len, nfq_data *nfa, const pcap_t *adhandle)
{
    IpHeader *pSrcIpHeader = (IpHeader *)pkt_data;
    int ipHeaderLen = (pSrcIpHeader->verIhl & 0x0F) * 4;
    TcpHeader *pTcp = (TcpHeader *)(pkt_data + ipHeaderLen);
    // 캡처한 IP 헤더에서 전체 길이를 가져와 TCP 페이로드 길이를 계산
    // int ipLen = ntohs(pSrcIpHeader->length);
    // int tcpHeaderLen = ((pTcp->data & 0xF0) >> 4) * 4;
    int payloadLen = ntohs(pSrcIpHeader->length) - ((pSrcIpHeader->verIhl & 0x0F) * 4) - (((pTcp->data & 0xF0) >> 4) * 4);
    // int payloadLen = ipLen - ipHeaderLen - tcpHeaderLen;

    struct nfqnl_msg_packet_hw *mac = nfq_get_packet_hw(nfa);
    if (mac)
    {
        uint64_t srcMacKey = 0;
        srcMacKey = MacToUint64(mac->hw_addr);
    }
    for (int i = 0; i < 2; i++)
    {

        unsigned char frameData[60] = {0}; // 최소 패킷 사이즈
        EtherHeader *pEtherHeader = (EtherHeader *)frameData;
        IpHeader *pIpHeader = (IpHeader *)(frameData + sizeof(EtherHeader));
        TcpHeader *pTcpHeader = (TcpHeader *)(frameData + sizeof(EtherHeader) + 20);

        // 1. Ethernet 설정: 나(VM) -> 클라이언트(Windows)
        if (i == DESTINATION::DST_SVR) // 클라 ->서버
        {
            memcpy(pEtherHeader->srcMac, mac->hw_addr, 6);
            memcpy(pEtherHeader->dstMac, g_ctx.config.gateway_mac, 6);
        }
        else if (i == DESTINATION::DST_CLI) // 서버->클라
        {
            memcpy(pEtherHeader->srcMac, g_ctx.config.gateway_mac, 6); // 내 리눅스 MAC
            memcpy(pEtherHeader->dstMac, mac->hw_addr, 6);             // 캡처된 패킷의 소스(클라) MAC
        }
        pEtherHeader->type = htons(0x0800);

        // 2. IP 설정: 서버 -> 클라이언트
        pIpHeader->verIhl = 0x45;
        pIpHeader->length = htons(40);
        pIpHeader->protocol = 6;
        pIpHeader->ttl = 128;

        if (i == DESTINATION::DST_SVR) // 클라 ->서버
        {
            memcpy(pIpHeader->srcIp, pSrcIpHeader->srcIp, 4);
            memcpy(pIpHeader->dstIp, &g_ctx.config.server_ip_addr, 4);
        }
        else if (i == DESTINATION::DST_CLI)
        {

            memcpy(pIpHeader->srcIp, &g_ctx.config.server_ip_addr, 4); // 서버 IP (가짜 출발지)
            memcpy(pIpHeader->dstIp, pSrcIpHeader->srcIp, 4);          // 클라이언트 IP
        }
        pIpHeader->checksum = CalcChecksumIp(pIpHeader);

        pTcpHeader->data = 0x50;
        pTcpHeader->flags = 0x04; // RST
        pTcpHeader->windowSize = 0;
        // 3. TCP 설정 (가장 중요)
        if (i == DESTINATION::DST_SVR) // 클라 ->서버
        {
            pTcpHeader->srcPort = pTcp->srcPort;
            pTcpHeader->dstPort = htons(g_ctx.config.server_port);
            pTcpHeader->ack = pTcp->ack; // 기존 ACK 유지

            uint32_t baseSeq = ntohl(pTcp->seq) + payloadLen;

            // uint32_t s_nextSeq = ntohl(pTcp->seq) + payloadLen;
            // pTcpHeader->seq = htonl(s_nextSeq);
            // pTcpHeader->seq = pTcp->seq;
            for (int burst = 0; burst < 3; burst++)
            {
                pTcpHeader->seq = htonl(baseSeq + (burst)); // 100바이트 간격으로 타격
                pTcpHeader->checksum = 0;
                pTcpHeader->checksum = CalcChecksumTcp(pIpHeader, pTcpHeader);

                pcap_sendpacket(const_cast<pcap_t *>(adhandle), frameData, 54);
            }
        }
        else if (i == DESTINATION::DST_CLI)
        {

            pTcpHeader->srcPort = htons(g_ctx.config.server_port); // 서버 포트
            pTcpHeader->dstPort = pTcp->srcPort;                   // 클라이언트 포트
            // 캡처한 패킷의 ACK를 나의 SEQ로 사용 (상대방이 기다리는 번호)
            pTcpHeader->seq = pTcp->ack;
            pTcpHeader->ack = 0;
            pTcpHeader->checksum = 0;
            pTcpHeader->checksum = CalcChecksumTcp(pIpHeader, pTcpHeader);

            // 4. 전송
            pcap_sendpacket(const_cast<pcap_t *>(adhandle), frameData, 54);
        }
    }
}

void PacketDetect::UpdateXdpBlcaklist(uint32_t src_ip)
{
    uint32_t value = 1;
    // m_xdp_black_map_fd는 프로그램 시작 시 오픈한 맵의 파일 디스크립터

    if (g_ctx.m_xdp_black_map_fd == -1)
    {
        printf("m_xdp_black_map_fd = -1 !");
    }

    if (bpf_map_update_elem(g_ctx.m_xdp_black_map_fd, &src_ip, &value, BPF_ANY) != 0)
    {
        fprintf(stderr, "Failed to update XDP map\n");
    }
    else
    {
        printf("[XDP] IP %u added to Kernel Blacklist!\n", src_ip);
    }
}

void PacketDetect::RemoveXdpBlcaklist(uint32_t srcip)
{
    if (g_ctx.m_xdp_black_map_fd == -1)
    {
        printf("m_xdp_black_map_fd = -1 !");
    }
    if (bpf_map_delete_elem(g_ctx.m_xdp_black_map_fd, &srcip) != 0)
    {
        fprintf(stderr, "Failed to delete XDP blacklist map element\n");
    }
    else
    {
        printf("[XDP] IP %u removed from Kernel Blacklist!\n", srcip);
    }
}

void PacketDetect::RemoveXdpWhitelist(uint32_t srcip)
{
    if (g_ctx.m_xdp_white_map_fd == -1)
    {
        printf("m_xdp_white_map_fd = -1 !");
    }
    if (bpf_map_delete_elem(g_ctx.m_xdp_white_map_fd, &srcip) != 0)
    {
        fprintf(stderr, "Failed to delete XDP whitelist map element\n");
    }
    else
    {
        printf("[XDP] IP %u removed from Kernel Whitelist!\n", srcip);
    }
}

void PacketDetect::UpdateXdpWhitelist(uint32_t srcip)
{
    uint32_t value = 1;
    // m_xdp_white_map_fd는 프로그램 시작 시 오픈한 맵의 파일 디스크립터

    if (g_ctx.m_xdp_white_map_fd == -1)
    {
        printf("m_xdp_white_map_fd = -1 !");
    }

    if (bpf_map_update_elem(g_ctx.m_xdp_white_map_fd, &srcip, &value, BPF_ANY) != 0)
    {
        fprintf(stderr, "Failed to update XDP whitelist map\n");
    }
    else
    {
        printf("[XDP] IP %u added to Kernel Whitelist!\n", srcip);
    }
}
