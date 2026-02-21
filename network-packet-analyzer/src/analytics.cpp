#include "npa/analytics.hpp"
#include <algorithm>
#include <functional>

namespace npa {

static std::size_t hcombine(std::size_t h1, std::size_t h2) {
  return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
}

std::size_t FlowKeyHash::operator()(const FlowKey& k) const {
  std::hash<std::string> hs;
  std::hash<uint16_t> hp;
  std::hash<uint8_t> hb;

  std::size_t h = 0;
  h = hcombine(h, hb(static_cast<uint8_t>(k.proto)));
  h = hcombine(h, hs(k.a.ip));
  h = hcombine(h, hp(k.a.port));
  h = hcombine(h, hs(k.b.ip));
  h = hcombine(h, hp(k.b.port));
  return h;
}

FlowKey Analytics::make_flow_key(const PacketInfo& p) {
  FlowProto fp = FlowProto::OTHER;
  if (p.l4 == L4Proto::TCP) fp = FlowProto::TCP;
  else if (p.l4 == L4Proto::UDP) fp = FlowProto::UDP;

  Endpoint e1{p.src_ip, p.src_port};
  Endpoint e2{p.dst_ip, p.dst_port};

  if (e2 < e1) std::swap(e1, e2);
  return FlowKey{fp, e1, e2};
}

static std::vector<TalkerEntry> topN_talkers(const std::unordered_map<std::string, uint64_t>& mp, int N) {
  if (N <= 0) return {};
  std::vector<TalkerEntry> v;
  v.reserve(mp.size());
  for (const auto& kv : mp) v.push_back({kv.first, kv.second});

  if ((int)v.size() > N) {
    std::nth_element(v.begin(), v.begin() + N, v.end(),
      [](const TalkerEntry& a, const TalkerEntry& b){ return a.bytes > b.bytes; });
    v.resize(N);
  }
  std::sort(v.begin(), v.end(), [](auto& a, auto& b){ return a.bytes > b.bytes; });
  return v;
}

static std::vector<HostEntry> topN_hosts(const std::unordered_map<std::string, uint64_t>& mp, int N) {
  if (N <= 0) return {};
  std::vector<HostEntry> v;
  v.reserve(mp.size());
  for (const auto& kv : mp) v.push_back({kv.first, kv.second});

  if ((int)v.size() > N) {
    std::nth_element(v.begin(), v.begin() + N, v.end(),
      [](const HostEntry& a, const HostEntry& b){ return a.hits > b.hits; });
    v.resize(N);
  }
  std::sort(v.begin(), v.end(), [](auto& a, auto& b){ return a.hits > b.hits; });
  return v;
}

void Analytics::ingest(const PacketInfo& p, uint64_t ts_ms) {
  if (!p.ipv4) return;

  src_bytes_[p.src_ip] += p.wirelen;
  dst_bytes_[p.dst_ip] += p.wirelen;

  FlowKey key = make_flow_key(p);
  auto it = flows_.find(key);
  if (it == flows_.end()) {
    FlowEntry fe;
    fe.key = key;
    fe.packets = 1;
    fe.bytes = p.wirelen;
    fe.first_seen_ms = ts_ms;
    fe.last_seen_ms = ts_ms;
    flows_.emplace(key, std::move(fe));
  } else {
    it->second.packets += 1;
    it->second.bytes += p.wirelen;
    it->second.last_seen_ms = ts_ms;
  }

  // NEW: HTTP Host hits
  if (p.http && !p.http_host.empty()) {
    http_host_hits_[p.http_host] += 1;
  }
}

std::vector<TalkerEntry> Analytics::top_src_talkers(int N) const { return topN_talkers(src_bytes_, N); }
std::vector<TalkerEntry> Analytics::top_dst_talkers(int N) const { return topN_talkers(dst_bytes_, N); }

std::vector<FlowEntry> Analytics::top_flows(int N) const {
  if (N <= 0) return {};
  std::vector<FlowEntry> v;
  v.reserve(flows_.size());
  for (const auto& kv : flows_) v.push_back(kv.second);

  if ((int)v.size() > N) {
    std::nth_element(v.begin(), v.begin() + N, v.end(),
      [](const FlowEntry& a, const FlowEntry& b){ return a.bytes > b.bytes; });
    v.resize(N);
  }
  std::sort(v.begin(), v.end(), [](auto& a, auto& b){ return a.bytes > b.bytes; });
  return v;
}

std::vector<HostEntry> Analytics::top_http_hosts(int N) const {
  return topN_hosts(http_host_hits_, N);
}

} // namespace npa
