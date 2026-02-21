#pragma once
#include <cstdint>
#include <functional>
#include <string>

namespace npa {

struct PcapPacket {
  const uint8_t* data;
  uint32_t caplen;
  uint32_t wirelen;

  // pointer valid during callback only
  const void* pcap_hdr; // actually points to pcap_pkthdr
};

class PcapCapture {
public:
  using Callback = std::function<void(const PcapPacket&)>;

  PcapCapture() = default;
  ~PcapCapture();

  // start capture loop on calling thread (usually run in std::thread)
  void run(const std::string& iface,
           const std::string& bpf_filter,
           bool promisc,
           int snaplen,
           Callback cb);

  void stop();

  void* native_handle() const { return handle_; } // pcap_t*

private:
  void* handle_ = nullptr; // pcap_t*
  bool stop_ = false;
};

} // namespace npa
