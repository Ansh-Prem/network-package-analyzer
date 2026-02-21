#pragma once
#include "npa/packet.hpp"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace npa {

struct TalkerEntry { std::string ip; uint64_t bytes = 0; };
struct HostEntry   { std::string host; uint64_t hits = 0; };

enum class FlowProto : uint8_t { TCP = 6, UDP = 17, OTHER = 0 };

struct Endpoint {
  std::string ip;
  uint16_t port = 0;
  bool operator<(const Endpoint& o) const {
    if (ip != o.ip) return ip < o.ip;
    return port < o.port;
  }
};

struct FlowKey {
  FlowProto proto;
  Endpoint a;
  Endpoint b;

  bool operator==(const FlowKey& o) const {
    return proto == o.proto &&
           a.ip == o.a.ip && a.port == o.a.port &&
           b.ip == o.b.ip && b.port == o.b.port;
  }
};

struct FlowKeyHash { std::size_t operator()(const FlowKey& k) const; };

struct FlowEntry {
  FlowKey key;
  uint64_t packets = 0;
  uint64_t bytes = 0;
  uint64_t first_seen_ms = 0;
  uint64_t last_seen_ms = 0;
};

class Analytics {
public:
  void ingest(const PacketInfo& p, uint64_t ts_ms);

  std::vector<TalkerEntry> top_src_talkers(int N) const;
  std::vector<TalkerEntry> top_dst_talkers(int N) const;
  std::vector<FlowEntry>   top_flows(int N) const;

  // NEW
  std::vector<HostEntry>   top_http_hosts(int N) const;

private:
  std::unordered_map<std::string, uint64_t> src_bytes_;
  std::unordered_map<std::string, uint64_t> dst_bytes_;
  std::unordered_map<FlowKey, FlowEntry, FlowKeyHash> flows_;

  // NEW
  std::unordered_map<std::string, uint64_t> http_host_hits_;

  static FlowKey make_flow_key(const PacketInfo& p);
};

} // namespace npa
