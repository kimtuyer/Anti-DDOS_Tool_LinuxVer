#include "PacketMonitor.h"
#include "Global.h"
#include "Util.h"
#include "PacketCapture.h"
#include "PacketDetect.h"
#include <csignal>

PacketMonitor *PacketMonitor::instance = nullptr;
PacketMonitor::PacketMonitor(const NetworkConfig &config, int mode, bool XDP)
	: m_mode(mode), bXDP(XDP)
{
	instance = this;
	// worker_queues.resize(NUM_WORKER_THREADS);

	std::signal(SIGINT, PacketMonitor::signal_handler);

	m_context = make_unique<SharedContext>(config);

	m_context->g_bRunning = true;
	m_packetDetect = make_unique<PacketDetect>(*m_context, m_mode, XDP);

	if (m_mode == eMode::MODE_NETFILTER)
	{
		m_netfilterCapture = make_unique<PacketCapture>(*m_context, m_packetDetect.get(), m_mode);
	}
	else
	{
		m_packetCapture = make_unique<PacketCapture>(*m_context, m_packetDetect.get(), m_mode);
	}
}

PacketMonitor::~PacketMonitor()
{
}

bool PacketMonitor::Initialize()
{
	/*if (!DataLoader::Load("config.json", m_config)) {
		printf("Can not Loading Config.json!");
		return false;
	}*/

	/*m_packetCapture = make_unique<PacketCapture>(worker_queues, blacklist_queue, m_config);
	m_packetDetect= make_unique<PacketDetect>(worker_queues, blacklist_queue, m_config);*/

	return true;
}

void PacketMonitor::Run(char *NicDriverName)
{

#ifdef __XDP__
	if (bXDP)
	{
		if (LoadXDP("filter.bpf.o", NicDriverName) == false)
		{
			printf("XDP Load Failed on device: %s\n", NicDriverName);
			return;
		}
	}
#endif
	if (m_mode == MODE_NETFILTER)
	{
#ifdef __NETFILTER__
		// 1. Netfilter 전용 캡처 객체 생성 및 실행
		// (기존 PacketCapture와 별도로 NetfilterCapture를 만들거나
		//  PacketCapture 내부에서 분기)
		m_netfilterCapture->Run();
#else
		printf("Netfilter mode is not compiled.\n");
#endif
	}
	else
	{
		m_packetCapture->Run();
	}
}

bool PacketMonitor::LoadXDP(const char *bpf_file, const char *if_name)
{

	int prog_fd;

	// 1. 오브젝트 파일 로드
	m_bpf_obj = bpf_object__open_file(bpf_file, NULL);
	if (!m_bpf_obj)
		return false;

	if (bpf_object__load(m_bpf_obj))
		return false;

	// 2. 프로그램 FD 가져오기
	struct bpf_program *prog = bpf_object__find_program_by_name(m_bpf_obj, "xdp_filter_main");
	prog_fd = bpf_program__fd(prog);

	// 3. 인터페이스(ens33 등)에 XDP 장착
	int ifindex = if_nametoindex(if_name);
	if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0)
	{
		fprintf(stderr, "Error: Failed to attach XDP to %s\n", if_name);
		return false;
	}

// 4. 블랙리스트 맵 FD 저장 (가장 중요!)
	m_context->m_xdp_global_map_fd = bpf_object__find_map_fd_by_name(m_bpf_obj, "global_pps_map");
	m_context->m_xdp_black_map_fd = bpf_object__find_map_fd_by_name(m_bpf_obj, "blacklist_map");
#ifdef __XDP_WHITELIST__
	m_context->m_xdp_white_map_fd = bpf_object__find_map_fd_by_name(m_bpf_obj, "whitelist_map");
	if (m_context->m_xdp_white_map_fd < 0)
	{
		fprintf(stderr, "Error: Failed to find whitelist_map\n");
		return false;
	}
#endif

	printf("[System] XDP attached. Global FD: %d, White FD: %d\n",
		   m_context->m_xdp_global_map_fd, m_context->m_xdp_white_map_fd);
	return true;
}

void PacketMonitor::UnloadXDP(const char *if_name)
{

	int ifindex = if_nametoindex(if_name);
	if (ifindex == 0)
		return;

	// FD에 -1을 주거나 0을 세팅하여 XDP 프로그램을 제거합니다.
	// 최신 libbpf에서는 bpf_set_link_xdp_fd(ifindex, -1, 0) 를 주로 사용합니다.
	if (bpf_set_link_xdp_fd(ifindex, -1, 0) < 0)
	{
		fprintf(stderr, "[Warning] XDP 언로드 실패: %s\n", if_name);
	}
	else
	{
		printf("[System] XDP filter successfully detached from %s\n", if_name);
	}
}

void PacketMonitor::signal_handler(int signal)
{
	printf("\n[System] 종료 시그널 감지. 자원 정리 중...\n");
	if (instance)
	{
		instance->UnloadXDP("ens33");
	}
	// ("ens33"); // 여기서 인터페이스 이름을 줍니다.
	exit(signal);
}
