#pragma once
#include "npa/packet.hpp"
#include "npa/analytics.hpp"
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>

namespace npa {

class Stats {
public:
  void ingest(const PacketInfo& p, uint64_t ts_ms);

  // NEW: added top_hosts
  std::string report_and_reset_interval(int top_talkers, int top_flows, int top_hosts);

private:
  std::atomic<uint64_t> total_packets_{0};
  std::atomic<uint64_t> total_bytes_{0};

  std::atomic<uint64_t> tcp_packets_{0};
  std::atomic<uint64_t> udp_packets_{0};
  std::atomic<uint64_t> other_packets_{0};

  std::atomic<uint64_t> interval_packets_{0};
  std::atomic<uint64_t> interval_bytes_{0};

  std::atomic<uint64_t> http_requests_{0};

  mutable std::mutex mx_;
  Analytics analytics_;
};

} // namespace npa
