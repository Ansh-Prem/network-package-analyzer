#include "npa/stats.hpp"
#include <sstream>

namespace npa {

void Stats::ingest(const PacketInfo& p, uint64_t ts_ms) {
  total_packets_.fetch_add(1, std::memory_order_relaxed);
  total_bytes_.fetch_add(p.wirelen, std::memory_order_relaxed);

  interval_packets_.fetch_add(1, std::memory_order_relaxed);
  interval_bytes_.fetch_add(p.wirelen, std::memory_order_relaxed);

  switch (p.l4) {
    case L4Proto::TCP: tcp_packets_.fetch_add(1, std::memory_order_relaxed); break;
    case L4Proto::UDP: udp_packets_.fetch_add(1, std::memory_order_relaxed); break;
    default: other_packets_.fetch_add(1, std::memory_order_relaxed); break;
  }

  if (p.http) http_requests_.fetch_add(1, std::memory_order_relaxed);

  {
    std::lock_guard<std::mutex> lk(mx_);
    analytics_.ingest(p, ts_ms);
  }
}

std::string Stats::report_and_reset_interval(int top_talkers, int top_flows, int top_hosts) {
  uint64_t ip = interval_packets_.exchange(0, std::memory_order_relaxed);
  uint64_t ib = interval_bytes_.exchange(0, std::memory_order_relaxed);

  uint64_t tp = total_packets_.load(std::memory_order_relaxed);
  uint64_t tb = total_bytes_.load(std::memory_order_relaxed);

  uint64_t tcp = tcp_packets_.load(std::memory_order_relaxed);
  uint64_t udp = udp_packets_.load(std::memory_order_relaxed);
  uint64_t oth = other_packets_.load(std::memory_order_relaxed);
  uint64_t http = http_requests_.load(std::memory_order_relaxed);

  std::ostringstream oss;
  oss << "Interval: packets=" << ip << ", bytes=" << ib
      << " | Total: packets=" << tp << ", bytes=" << tb
      << " | proto: TCP=" << tcp << " UDP=" << udp << " OTHER=" << oth
      << " | HTTP(req)=" << http;

  std::lock_guard<std::mutex> lk(mx_);

  if (top_talkers > 0) {
    auto topSrc = analytics_.top_src_talkers(top_talkers);
    auto topDst = analytics_.top_dst_talkers(top_talkers);

    oss << "\n  Top SRC talkers(bytes): ";
    for (const auto& t : topSrc) oss << t.ip << "=" << t.bytes << "  ";

    oss << "\n  Top DST talkers(bytes): ";
    for (const auto& t : topDst) oss << t.ip << "=" << t.bytes << "  ";
  }

  if (top_flows > 0) {
    auto flows = analytics_.top_flows(top_flows);
    oss << "\n  Top Flows(bytes):";
    for (const auto& f : flows) {
      std::string proto = "OTH";
      if (f.key.proto == FlowProto::TCP) proto = "TCP";
      else if (f.key.proto == FlowProto::UDP) proto = "UDP";

      oss << "\n    " << proto << " "
          << f.key.a.ip << ":" << f.key.a.port
          << " <-> "
          << f.key.b.ip << ":" << f.key.b.port
          << " bytes=" << f.bytes << " pkts=" << f.packets;
    }
  }

  if (top_hosts > 0) {
    auto hosts = analytics_.top_http_hosts(top_hosts);
    oss << "\n  Top HTTP Hosts(hits): ";
    for (const auto& h : hosts) oss << h.host << "=" << h.hits << "  ";
  }

  return oss.str();
}

} // namespace npa
