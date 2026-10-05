# Punching Bag

## Overview

Punching Bag is an IPv6 ICMP echo responder designed for network testing and simulation scenarios. 
It listens for ICMPv6 Echo Requests (`ping`) on a specified network interface and responds with ICMPv6 Echo Replies according to configurable prefix-based response rates.  
The tool uses `libpcap` for packet capture, `libnet` for packet crafting, and a trie-based IPv6 prefix table (loaded from a JSON configuration) to determine probabilistic reply behavior.

The tool was created as part of our publication ["Punching Bag: A Tool for Testing IPv6 Scans and Target Generation Algorithms"](https://dl.acm.org/doi/10.1145/3777912.3839826), presented at the [ACM Internet Measurement Conference 2026](https://conferences.sigcomm.org/imc/2026).
If you use our tool, please cite our publication as shown [below](#citation).
The code was written by Christian Junginger with minor changes made by Lion Steger.

---

## Features
- **Simulate ICMPv6 echo responses** using multithreaded workers.
- **Prefix-based probability response rates** via an IPv6 trie.
- **Configurable thread count, pcap capture timeout, and max queue size**.
- **Queue monitoring and logging** with timestamped performance stats.
- **Graceful shutdown** via `CTRL+C` with cleanup of all threads.
- **Efficient packet processing** with minimal overhead.

---

## Requirements

### Build Dependencies
- C++17 compiler
- CMake ≥ 3.10
- [libpcap](https://www.tcpdump.org/)
- [libnet](https://github.com/libnet/libnet)
- [nlohmann JSON](https://github.com/nlohmann/json)
- pthreads (POSIX threads)

Install via apt:

```bash
apt install libnet-dev nlohmann-json3-dev
```

### Runtime Requirements
- Root or equivalent permissions (required for raw socket operations)
- A valid JSON configuration file with IPv6 prefixes and response rates (examples are provided in JSON_configs)

---

## Building

```bash
mkdir build && cd build
cmake ..
make
```

This produces the executable:

```
./punchingbag
```

---

## Command-line Arguments

| Argument | Description | Required | Default |
|----------|-------------|----------|---------|
| `--interface=<iface>` | Network interface to listen on (e.g., `eth0`) | Yes | — |
| `--json-config=<path>` | Path to JSON file containing IPv6 prefixes and response rates | Yes | — |
| `--thread-count=<n>` | Number of worker threads | No | `1` |
| `--pcap-timeout=<ms>` | Timeout for `pcap` capture loop in milliseconds | No | `50` |
| `--max-queue-size=<n>` | Maximum packet queue length before dropping packets | No | `250.000` |
| `--random-responses` | Replaces deterministic random responses with true random respones | No |  |

---

## JSON Configuration Format

Example `prefixes.json`:
```json
{
  "subnets": [
    {
      "ipv6_prefix": "2001:db8:abcd:12::/64",
      "default_response_rate": 0.01,
      "EUI_response_rate": 0.0,
      "lower_response_rate": 1.0,
      "higher_response_rate": 0.5
    }
  ]
}
```
- `prefix` — IPv6 prefix in CIDR notation
- `response_rate` — Probability (0.0–1.0) of replying to a ping

---

## Logging

The program generates a queue log file named:
```
queue_log_YYYY-MM-DD_HH-MM-SS.txt
```
This file contains:
- Queue size
- Queue usage percentage
- Total received packets
- Libnet write error count
- Timestamps

---

## Internals

**Main components:**
- **Packet capture**: `pcap_loop` filters and queues ICMPv6 Echo Requests.
- **Worker threads**: Process queued packets and send responses based on trie lookup.
- **IPv6 trie**: Efficient prefix matching with configurable probabilities.
- **Logger thread**: Periodically logs queue statistics to a file.

**BPF filter used**:
```text
icmp6 and ip6[40] == 128
```
This ensures only ICMPv6 Echo Requests are captured.

## Citation

```
@inproceedings{steger2026punching,
  author = {Steger, Lion and Junginger, Christian and Carle, Georg and Zirngibl, Johannes},
  title = {{Punching Bag: A Tool for Testing IPv6 Scans and Target Generation Algorithms}},
  year = {2026},
  isbn = {9798400723278},
  publisher = {Association for Computing Machinery},
  address = {New York, NY, USA},
  url = {https://doi.org/10.1145/3777912.3839826},
  doi = {10.1145/3777912.3839826},
  booktitle = {Proceedings of the 2026 ACM Internet Measurement Conference},
  pages = {219-227},
  numpages = {9},
  keywords = {IPv6, target generation algorithms},
  location = {Karlsruhe Institute of Technology, Karlsruhe, Germany},
  series = {IMC '26},
}

```