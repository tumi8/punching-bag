
#include <iostream>
#include <pcap.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <thread>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <queue>
#include <mutex>
#include <net/if.h>
#include <condition_variable>
#include <vector>
#include <csignal>
#include <chrono>
#include <memory>
#include <random>
#include <atomic>
#include <libnet.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime> 

#include "IPv6-trie.hpp"

struct PacketEntry {
    in6_addr src_addr;
    in6_addr dst_addr;
    uint8_t icmp_type;
    uint16_t echo_id;
    uint16_t echo_seq;
    std::vector<uint8_t> data;
};

std::queue<PacketEntry> packet_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;

// shutdown flag is set when CTRL + C is recieved on std::cin
std::atomic<bool> shutdown_flag = false;

// counter for conflicted writes from libnet
std::atomic<size_t> failed_writes_counter {0};

// counter for received packets
std::atomic<size_t> recieved_packets {0};
pcap_t* global_pcap_handle = nullptr;

// max_queue_size
size_t max_queue_size = 250000;

std::ofstream packet_log("packet_log.txt", std::ios::out | std::ios::binary);

void send_icmpv6_response(libnet_t* l, const PacketEntry& entry) {
    if (entry.icmp_type != ICMP6_ECHO_REQUEST)
        return;

    libnet_clear_packet(l);

    libnet_ptag_t icmp_tag = libnet_build_icmpv6_echo(
        ICMP6_ECHO_REPLY,
        0,
        0,
        htons(entry.echo_id),
        htons(entry.echo_seq),
        const_cast<uint8_t*>(entry.data.data()),
        entry.data.size(),
        l,
        0
    );

    if (icmp_tag == -1) {
        std::cerr << "Error building ICMPv6: " << libnet_geterror(l) << std::endl;
        return;
    }

    libnet_ptag_t ipv6_tag = libnet_build_ipv6(
        0,
        0,
        LIBNET_ICMPV6_ECHO_H + entry.data.size(),
        IPPROTO_ICMPV6,
        64,
        *(libnet_in6_addr*)&entry.dst_addr,
        *(libnet_in6_addr*)&entry.src_addr,
        nullptr,
        0,
        l,
        0
    );

    if (ipv6_tag == -1) {
        std::cerr << "Error building IPv6 header: " << libnet_geterror(l) << std::endl;
        return;
    }

    int bytes = libnet_write(l);
    if (bytes < 0) {
        std::cerr << "libnet_write() failed: " << libnet_geterror(l) << std::endl;
    }
}

std::size_t hash_ipv6_fast(const in6_addr& addr) {
    uint64_t high, low;
    std::memcpy(&high, addr.s6_addr, 8);
    std::memcpy(&low, addr.s6_addr + 8, 8);
    std::size_t h1 = std::hash<uint64_t>{}(high);
    std::size_t h2 = std::hash<uint64_t>{}(low);
    return std::hash<uint64_t>{}(h1 ^ h2);
}

void worker_thread(std::shared_ptr<const Node> ipv6_trie, const std::string& interface_name, bool random_responses) {
    static thread_local int processed_count = 0;

    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t* l = libnet_init(LIBNET_RAW6, nullptr, errbuf);
    if (!l) {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        return;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);

    while (true) {
        std::unique_lock<std::mutex> lock(queue_mutex);
        queue_cv.wait(lock, [] { return !packet_queue.empty() || shutdown_flag.load(); });

        if (shutdown_flag && packet_queue.empty())
            break;

        if (packet_queue.empty())
            continue;

        PacketEntry entry = std::move(packet_queue.front());
        packet_queue.pop();
        lock.unlock();

        processed_count++;

        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &entry.dst_addr, addr_str, sizeof(addr_str));
        float response_rate = ipv6_trie->getResponseRateForAddress(std::string(addr_str)) * 1000;

        double random_value = 0;
        if (random_responses) {
            random_value = dis(gen) * 1000;
        } else {
            size_t ip_hash = hash_ipv6_fast(entry.dst_addr);
            random_value = ip_hash % 1000;
        }

        if (random_value < response_rate) {
           send_icmpv6_response(l, entry);
        }
    }

     libnet_destroy(l);
}

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    const struct ip6_hdr* ipv6_hdr = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
    const struct icmp6_hdr* icmp6_hdr = (struct icmp6_hdr*)((u_char*)ipv6_hdr + sizeof(struct ip6_hdr));
    const u_char* icmp6_payload = (u_char*)icmp6_hdr + sizeof(struct icmp6_hdr);

    PacketEntry entry;
    entry.src_addr = ipv6_hdr->ip6_src;
    entry.dst_addr = ipv6_hdr->ip6_dst;
    entry.icmp_type = icmp6_hdr->icmp6_type;
    entry.echo_id = icmp6_hdr->icmp6_id;
    entry.echo_seq = icmp6_hdr->icmp6_seq;

    size_t payload_length = header->caplen - ((const u_char*)icmp6_payload - packet);
    entry.data.assign(icmp6_payload, icmp6_payload + payload_length);

    {
        std::unique_lock<std::mutex> lock(queue_mutex);

        char addrStr[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &entry.dst_addr, addrStr, sizeof(addrStr)) == nullptr) {
            std::cerr << "inet_ntop failed: " << strerror(errno) << "\n";
            return;
        }
        
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
        
        packet_log << timestamp << "," << addrStr << "\n";

        // When max_queue_size is reached punchingbag will wait to 
        if (packet_queue.size() >= max_queue_size) {
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            return;
        }
        packet_queue.push(std::move(entry));
    }

    recieved_packets++;
    queue_cv.notify_one();
}

void signal_handler(int) {
    shutdown_flag = true;
    std::cout << "Shutdown triggered!\n";
    queue_cv.notify_all();
    if (global_pcap_handle)
        pcap_breakloop(global_pcap_handle);
}

void queue_logger_thread() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm* now_tm = std::localtime(&now_c);

    std::ostringstream filename_stream;
    filename_stream << "queue_log_"
        << std::put_time(now_tm, "%Y-%m-%d_%H-%M-%S")
        << ".txt";

    std::string filename = filename_stream.str();

    std::ofstream logfile(filename, std::ios::out);

    if (!logfile) {
        std::cerr << "Failed to open log file.\n";
        return;
    }

    while (!shutdown_flag.load()) {
        size_t queue_size = 0;

        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            queue_size = packet_queue.size();
        }

        if (queue_size > 0) {
            double usage_percent = (max_queue_size > 0) ? (static_cast<double>(queue_size) * 100.0 / max_queue_size) : 0.0;

            // Generate current timestamp
            now = std::chrono::system_clock::now();
            std::time_t now_time = std::chrono::system_clock::to_time_t(now);
            std::tm* local_tm = std::localtime(&now_time);

            std::ostringstream oss;
            oss << "[" << std::put_time(local_tm, "%Y-%m-%d %H:%M:%S") << "]: ";

            // Log queue size with timestamp
            logfile << oss.str() 
                << "Queue size: " << queue_size
                << ", Usage: " << usage_percent << "%"
                << ", Received packets: " << recieved_packets
                << ", Libnet errors: " << failed_writes_counter
                << std::endl;

            logfile.flush();
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Log final queue size at shutdown (with timestamp)
    now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm* local_tm = std::localtime(&now_time);

    std::ostringstream oss;
    oss << "[" << std::put_time(local_tm, "%Y-%m-%d %H:%M:%S") << "]";
    logfile << oss.str() << " Logger shutting down." << "\n" 
        << "Final queue size: " << packet_queue.size() << "\n"
        << "Recieved packets: " << recieved_packets << "\n"
        << "Libnet errors: " << failed_writes_counter << "\n";

    logfile.close();
}

int main(int argc, char* argv[]) {
    std::string interface;
    std::string json_config;
    int num_workers = 1;
    bool random_responses = false;

    // default flush timer is set to 50 ms. 
    // In experiments where the maximal response rate of punchingbag wasn't exceeded, the maximal ping_time reached up to the flushtimer + the overhead of punchingbag
    // previous default was 1000 which lead to pings with 1024ms
    int pcap_timeout = 50;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);

        if (arg.rfind("--interface=", 0) == 0) {
            interface = arg.substr(12);
        } else if (arg.rfind("--json-config=", 0) == 0) {
            json_config = arg.substr(14);
        } else if (arg.rfind("--thread-count=", 0) == 0) {
            try {
                num_workers = std::stoi(arg.substr(15));
                if (num_workers <= 0) throw std::invalid_argument("Must be positive");
            } catch (...) {
                std::cerr << "Invalid value for --thread-count\n";
                return 1;
            }
        } else if (arg.rfind("--pcap-timeout=", 0) == 0) {
            try {
                pcap_timeout = std::stoi(arg.substr(15));
                if (pcap_timeout <= 0) throw std::invalid_argument("Must be positive");
            } catch (...) {
                std::cerr << "Invalid value for --pcap-timeout\n";
                return 1;
            }
        } else if (arg.rfind("--max-queue-size=", 0) == 0) {
            try {
                max_queue_size = std::stoi(arg.substr(17));
                if (max_queue_size <= 0) throw std::invalid_argument("Must be positive");
            } catch (...) {
                std::cerr << "Invalid value for --max-queue-size\n";
                return 1;
            }
        } else if (arg.rfind("--random-responses", 0) == 0) {
            random_responses = true;
        }
        else {
            std::cerr << "Unknown argument: " << arg << "\n";
            return 1;
        }
    }

    if (interface.empty()) {
        std::cerr << "Error: --interface must be specified\n";
        return 1;
    }

    if (json_config.empty()) {
        std::cerr << "Error: --json-config must be specified\n";
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::shared_ptr<Node> trie = std::make_shared<Node>();

    try {
        trie->insertPrefixesFromJSON(json_config);
    } catch (const std::exception& e) {
        std::cerr << "Error loading prefix trie: " << e.what() << "\n";
        return 1;
    }

    std::thread logger_thread(queue_logger_thread);

    std::vector<std::thread> workers;
    for (int i = 0; i < num_workers; ++i) {
        workers.emplace_back(worker_thread, trie, interface, random_responses);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 0, 100, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << "\n";
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "icmp6 and ip6[40] == 128", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Failed to set BPF filter\n";
        return 1;
    }
    global_pcap_handle = handle;
    std::cout << "Listening on " << interface << " for ICMPv6 packets...\n";
    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);

    for (auto& worker : workers) {
        worker.join();
    }
    logger_thread.join();

    packet_log.flush();

    return 0;
}

