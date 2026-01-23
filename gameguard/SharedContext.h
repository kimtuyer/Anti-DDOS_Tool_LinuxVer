#pragma once
#include "define.h"
#include "DataLoader.h"

//리눅스용
template <typename T>
class ThreadSafeQueue {
private:
    std::queue<T> q;
    std::mutex m;
public:
    void push(T val) {
        std::lock_guard<std::mutex> lock(m);
        q.push(val);
    }
    bool try_pop(T& val) {
        std::lock_guard<std::mutex> lock(m);
        if (q.empty()) return false;
        val = q.front();
        q.pop();
        return true;
    }
};


// 워커 스레드 1명이 가질 전용 데이터 세트
struct WorkerContext {
    // 1. 전용 큐
    std::unordered_map<uint32_t, std::pair<Packet, PacketCount>> packetlist;

    std::set<uint32_t> whitelist;
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> greylist;
    // ★ 추가: MAC별 통계 (Key: MAC주소 정수값, Value: 패킷 수)
    std::unordered_map<uint64_t, int> mac_stat;


    // 2. 전용 락과 알림벨 (이 스레드만 쳐다봄)
    std::mutex q_mutex;
    std::condition_variable q_cv;

    // 복사 금지 (mutex, cv 때문)
    WorkerContext() = default;
    WorkerContext(const WorkerContext&) = delete;
    WorkerContext& operator=(const WorkerContext&) = delete;
};

// 워커 스레드들이 공유할 모든 자원
struct SharedContext {
    atomic<bool>g_bRunning{true};
    // 1. 데이터 큐
    //std::vector<std::map<uint32_t, std::pair<Packet, int>>> worker_queues;
    std::vector<std::unique_ptr<WorkerContext>> workers;

    ThreadSafeQueue<uint32_t> blacklist_queue;
    //concurrency::concurrent_queue<uint32_t> blacklist_queue;

    // 2. 동기화 객체 (Condition Variable 필수품)
    // cpu코어간에 같은 캐시라인에 속해 False Sharing 성능 우려 있음. 
    //mutex m1[NUM_WORKER_THREADS];
    //std::condition_variable cv[NUM_WORKER_THREADS];

    atomic<bool> g_emergency_mode{false};
    std::atomic<int> g_syn_count{0};
    std::atomic<int> g_ack_count{0};

    int m_xdp_global_map_fd{-1};  //XDP 사용하는 블랙리스트 맵 FD
    int m_xdp_black_map_fd{-1};  //XDP 사용하는 블랙리스트 맵 FD

    int m_xdp_white_map_fd{-1};  //XDP 화이트리스트 맵 FD

    // 3. 설정 파일
    const NetworkConfig config;

    // 생성자 (설정 파일 초기화 등)
    SharedContext(const NetworkConfig& cfg) : config(cfg) {

        for (int i = 0; i < NUM_WORKER_THREADS; ++i) {
            workers.push_back(std::make_unique<WorkerContext>());
        }
    }
};