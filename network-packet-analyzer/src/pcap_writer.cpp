#include "npa/pcap_writer.hpp"
#include <stdexcept>

namespace npa {

PcapWriter::~PcapWriter() { close(); }

void PcapWriter::open(pcap_t* handle, const std::string& filename) {
  if (filename.empty()) return;
  if (!handle) throw std::runtime_error("PcapWriter::open: null pcap handle");

  dumper_ = pcap_dump_open(handle, filename.c_str());
  if (!dumper_) {
    throw std::runtime_error("pcap_dump_open failed (check path/permissions)");
  }
}

void PcapWriter::write(const pcap_pkthdr* hdr, const u_char* bytes) {
  if (!dumper_ || !hdr || !bytes) return;
  pcap_dump(reinterpret_cast<u_char*>(dumper_), hdr, bytes);
}

void PcapWriter::close() {
  if (dumper_) {
    pcap_dump_close(dumper_);
    dumper_ = nullptr;
  }
}

} // namespace npa
