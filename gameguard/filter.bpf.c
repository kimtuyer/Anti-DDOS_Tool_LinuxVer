#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // 이 헤더가 있으면 __bpf_htonl 사용 가능
#define __XDP_GLOBAL__      // Rand-IP 공격에 대응하기 위한 글로벌 맵 정의
#define __PERCPU__          // 다중 CPU 코어별 카운팅
#define __XDP_WHITELIST__   // 신뢰할 수 있는 클라이언트 IP는 화이트리스트로 관리
const int SERVER_CNT = 4;

#ifdef __XDP_GLOBAL__
struct
{
#ifdef __PERCPU__
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // 단일 값을 저장하기 위해 Array 사용
#else
    __uint(type, BPF_MAP_TYPE_ARRAY); // 단일 값을 저장하기 위해 Array 사용
#endif
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_pps_map SEC(".maps");

#ifdef __XDP_WHITELIST__
// 신뢰할 수 있는 클라이언트 IP를 저장하는 화이트리스트 맵
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64)); // 통과된 시각 등을 저장 가능
} whitelist_map SEC(".maps");
#endif

// 1. 블랙리스트 IP를 저장할 eBPF 맵 정의
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);        // 최대 1만개 IP 차단
    __uint(key_size, sizeof(__u32));   // IP 주소
    __uint(value_size, sizeof(__u32)); // 차단 여부 (보통 1)
} blacklist_map SEC(".maps");

#endif

static __always_inline void update_csum16(__u16 *csum, __u16 old_val, __u16 new_val)
{
    __u32 new_csum_value;
    __u32 tmp_csum = ~(*csum) & 0xFFFF; // 1. 현재 체크섬의 반전값(합계)을 구함
    __u32 tmp_old = ~old_val & 0xFFFF;  // 2. 예전 값의 반전
    __u32 tmp_new = new_val & 0xFFFF;   // 3. 새 값

    // 공식: new_csum = ~(~old_csum + ~old_val + new_val)
    new_csum_value = tmp_csum + tmp_old + tmp_new;

    // 16비트 오버플로우(Carry) 처리
    new_csum_value = (new_csum_value & 0xFFFF) + (new_csum_value >> 16);
    *csum = ~((__u16)new_csum_value);
}
unsigned short CalPortNumber(int hashkey)
{
    switch (hashkey)
    {
    case 0:
        return bpf_htons(25001);
    case 1:
        return bpf_htons(25002);
    case 2:
        return bpf_htons(25003);
    case 3:
        return bpf_htons(25004);
    default:
        return -1;
    }
    return -1;
}
int LoadBlancedPort(struct ethhdr *eth, struct iphdr *iph, struct tcphdr *tcp)
{
    if (tcp == NULL || iph == NULL || eth == NULL)
        return XDP_DROP;

    int hashkey = (iph->saddr + tcp->dest) % SERVER_CNT;

    unsigned short oldport = tcp->dest;
    unsigned short newport = CalPortNumber(hashkey);
    if (newport == (unsigned short)-1)
    {
        char fmt[] = "PORT HASHING FAIL!:%llu\n";
        bpf_trace_printk(fmt, sizeof(fmt), newport);
        return XDP_DROP;
    }
    tcp->dest = newport;
    // 포트번호 변경 인한 새로 체크섬 계산!
    //__u32 csum_off = offsetof(struct tcphdr, check);
    __u32 old_val = oldport;
    __u32 new_val = newport;
    update_csum16(&tcp->check, oldport, newport);

    /* * [핵심] MAC 주소 교체 로직
     * 실제 환경에서는 각 서버의 MAC 주소를 Map에 저장해두고 꺼내 써야 하지만,
     * 테스트 환경에서는 우선 Source/Dest MAC을 서로 맞바꾸는(Swap) 식으로 응답 가능 여부를 확인합니다.
     */

    //테스트 환경에선 백엔드 서버가 같은 vm안에 위치하므로 mac주소 스왑후 XDP_TX 처리가 어려움.
    // unsigned char tmp_mac[ETH_ALEN];
    // __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    // __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    // __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    // 3. 목적지 IP도 해당 서버 IP로 바꿔줘야 함 (필요 시)
    // iph->daddr = target_server_ip;
    // update_csum32(&iph->check, old_ip, target_server_ip);
    return XDP_PASS;
}

SEC("xdp")
int xdp_filter_main(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 2. 이더넷 헤더 파싱
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 3. IPv4 패킷만 처리
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(iph + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // ★ SSH(22) 포트로 가는 패킷은 블랙리스트 검사 전 무조건 통과
    if (tcp->dest == bpf_htons(22) || tcp->source == bpf_htons(22))
    {
        return XDP_PASS;
    }
#ifdef __XDP_GLOBAL__
    __u32 key = 0;
    __u64 *total_count = bpf_map_lookup_elem(&global_pps_map, &key);
    __u32 src_ip = iph->saddr;
    if (total_count)
    {
#ifdef __PERCPU__
        *total_count += 1;
        // char fmt1[] = "total count:%llu\n";
        // bpf_trace_printk(fmt1, sizeof(fmt1), *total_count);
#else
        __sync_fetch_and_add(total_count, 1);
#endif
        //  블랙리스트 맵에서 소스 IP 조회
        __u32 src_ip = iph->saddr;
        __u32 *value = bpf_map_lookup_elem(&blacklist_map, &src_ip);
        if (value)
        {
            // 블랙리스트에 있으면 유저모드로 안 보내고 즉시 삭제!
            return XDP_DROP;
        }

#ifdef __XDP_WHITELIST__
        // 화이트리스트 맵에서 소스 IP 조회
        __u64 *whitelist_entry = bpf_map_lookup_elem(&whitelist_map, &src_ip);
        if (whitelist_entry)
        {
            // 화이트리스트에 있으면 유저모드로 안 보내고 즉시 통과!
            if (LoadBlancedPort(eth, iph, tcp) != XDP_DROP)
                return XDP_PASS;//XDP_TX <-벡엔드 서버가 같은 vm안에 위치하므로 포트/맥주소 변경한 상태라 XDP_TX로 리턴함.
            else
                return XDP_DROP;
        }
#endif
        if (*total_count > 2500)
        { // 초당 전체 SYN이 1만개를 넘으면
            char fmt[] = "DROP TRIGGERED! count:%llu\n";
            bpf_trace_printk(fmt, sizeof(fmt), *total_count);
            if (src_ip == bpf_htonl(0xC0A81501)) // 내 호스트 ip는 통과
            {
                return XDP_PASS;
            }
            return XDP_DROP;
        }
    }

#endif

    // 정상 패킷은 기존대로 Netfilter 스택으로 보냄
    // 화이트리스트는 아니지만, 일단 로드밸런싱 포트로 변환은 해줌
    if (LoadBlancedPort(eth, iph, tcp) == XDP_DROP)
        return XDP_DROP;
    //테스트 환경이라 백엔드서버가 같은 vm안에 위치하므로 XDP_TX로 응답 불가.
    // char fmt[] = "UserMode Toss!\n";
    // bpf_trace_printk(fmt, sizeof(fmt));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";