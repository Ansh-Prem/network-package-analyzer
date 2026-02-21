#pragma once
#include <string>

namespace npa {

struct Config {
  std::string iface;
  std::string filter;
  bool promisc = true;
  int snaplen = 65535;
  int stats_every_sec = 1;
  bool verbose = false;

  std::string pcap_out;
  int top_talkers = 5;
  int top_flows = 5;

  // NEW
  int top_hosts = 5; // Top HTTP hosts (0 disables)
};

Config parse_args(int argc, char** argv);

} // namespace npa
