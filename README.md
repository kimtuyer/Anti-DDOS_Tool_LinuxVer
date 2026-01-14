1.요약
eBPF/XDP 기반의 고성능 커널 레벨 차단 엔진을 탑재한 지능형 Anti-DDoS 솔루션

2. 핵심 기술 스택
README 상단에 배치하여 면접관의 시선을 끌 수 있는 기술 요약입니다.

Zero-Copy Packet Dropping: 리눅스 커널 입구(XDP)에서 공격 패킷을 즉시 파기하여 CPU 오버헤드 최소화.

User-Kernel Collaborative Defense: 유저 모드의 정교한 상태 분석(Stateful Analysis)과 커널 모드의 초고속 차단(Hardware-level Speed) 결합.

Stateful SYN Flood Detection: 단순 임계치를 넘어 SYN/ACK 비율 분석 및 Emergency Mode(First Drop) 로직 구현.

Multi-threaded Engine: 고성능 패킷 처리를 위한 멀티스레딩 및 std::shared_mutex 기반의 Lock-free 지향 설계.

3. 프로젝트 소개
본 프로젝트는 리눅스 환경에서 대규모 네트워크 공격(SYN Flood 등)을 효율적으로 방어하기 위해 개발되었습니다. 처음에는 Pcap 기반의 Out-of-Path 방식으로 서버로 가는 패킷을 캡쳐해 공격 패킷일 경우 차단하는
사후 처리 방식이었으나,  Netfilter(NFQUEUE) 방식의 인라인 방식을 도입하여 사전에 길목에서 먼저 차단할 수 있게 되었습니다. 하지만 Netfilter 방식의 인라인 검사가 가진 CPU 자원 소모 한계를 극복하고자,
eBPF/XDP 기술을 도입하여 방어 성능을 극대화했습니다.

공격 탐지는 유저 모드에서 수행하여 유연한 정책 적용이 가능하며, 탐지된 공격 IP는 실시간으로 커널의 eBPF Blacklist Map에 동기화되어 CPU 점유율을 16.6%에서 2.3%로 약 7배 이상 절감하는 성과를 거두었습니다.
