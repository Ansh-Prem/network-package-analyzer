#include "npa/pcap_capture.hpp"
#include <pcap/pcap.h>
#include <stdexcept>
#include <string>

namespace npa {

struct DispatchUser {
  PcapCapture::Callback* cb;
};

static void pcap_dispatch_cb(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
  auto* u = reinterpret_cast<DispatchUser*>(user);
  PcapPacket p{
    reinterpret_cast<const uint8_t*>(bytes),
    static_cast<uint32_t>(h->caplen),
    static_cast<uint32_t>(h->len),
    h
  };
  (*(u->cb))(p);
}

PcapCapture::~PcapCapture() {
  if (handle_) {
    pcap_close(reinterpret_cast<pcap_t*>(handle_));
    handle_ = nullptr;
  }
}

void PcapCapture::run(const std::string& iface,
                      const std::string& bpf_filter,
                      bool promisc,
                      int snaplen,
                      Callback cb) {
  char errbuf[PCAP_ERRBUF_SIZE]{0};

  pcap_t* p = pcap_open_live(iface.c_str(), snaplen, promisc ? 1 : 0, 1000, errbuf);
  if (!p) throw std::runtime_error(std::string("pcap_open_live failed: ") + errbuf);

  handle_ = p;

  // Compile + set BPF filter
  bpf_program fp{};
  if (!bpf_filter.empty()) {
    if (pcap_compile(p, &fp, bpf_filter.c_str(), 1 /* optimize */, PCAP_NETMASK_UNKNOWN) < 0) {
      throw std::runtime_error(std::string("pcap_compile failed: ") + pcap_geterr(p));
    }
    if (pcap_setfilter(p, &fp) < 0) {
      pcap_freecode(&fp);
      throw std::runtime_error(std::string("pcap_setfilter failed: ") + pcap_geterr(p));
    }
    pcap_freecode(&fp);
  }

  stop_ = false;
  DispatchUser u{&cb};

  while (!stop_) {
    int rc = pcap_dispatch(p, 64, pcap_dispatch_cb, reinterpret_cast<u_char*>(&u));
    if (rc < 0) break; // error or breakloop
  }
}

void PcapCapture::stop() {
  stop_ = true;
  if (handle_) {
    pcap_breakloop(reinterpret_cast<pcap_t*>(handle_));
  }
}

} // namespace npa
