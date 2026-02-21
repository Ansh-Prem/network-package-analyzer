#pragma once
#include <pcap/pcap.h>
#include <string>

namespace npa {

class PcapWriter {
public:
  PcapWriter() = default;
  ~PcapWriter();

  void open(pcap_t* handle, const std::string& filename);
  void write(const pcap_pkthdr* hdr, const u_char* bytes);
  void close();

  bool enabled() const { return dumper_ != nullptr; }

private:
  pcap_dumper_t* dumper_ = nullptr;
};

} // namespace npa
