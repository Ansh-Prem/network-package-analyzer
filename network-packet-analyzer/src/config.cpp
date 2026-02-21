#include "npa/config.hpp"
#include <boost/program_options.hpp>
#include <iostream>

namespace npa {

Config parse_args(int argc, char** argv) {
  namespace po = boost::program_options;

  Config cfg;
  po::options_description desc("Network Packet Analyzer options");

  desc.add_options()
    ("help,h", "Show help")
    ("iface,i", po::value<std::string>(&cfg.iface)->default_value("eth0"), "Interface to capture on")
    ("filter,f", po::value<std::string>(&cfg.filter)->default_value("tcp or udp"), "BPF filter")
    ("promisc", po::value<bool>(&cfg.promisc)->default_value(true), "Promiscuous mode (true/false)")
    ("snaplen", po::value<int>(&cfg.snaplen)->default_value(65535), "Snap length")
    ("stats-every", po::value<int>(&cfg.stats_every_sec)->default_value(1), "Print stats every N seconds")
    ("verbose,v", po::bool_switch(&cfg.verbose), "Verbose output")

    ("pcap-out", po::value<std::string>(&cfg.pcap_out)->default_value(""),
      "Write captured packets to this .pcap file (Wireshark compatible)")
    ("top-talkers", po::value<int>(&cfg.top_talkers)->default_value(5),
      "Print top N SRC/DST talkers by bytes (0 disables)")
    ("top-flows", po::value<int>(&cfg.top_flows)->default_value(5),
      "Print top N flows (5-tuple, canonicalized) by bytes (0 disables)")

    // NEW
    ("top-hosts", po::value<int>(&cfg.top_hosts)->default_value(5),
      "Print top N HTTP Host headers (plaintext HTTP only) (0 disables)")
  ;

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help")) {
    std::cout << desc << "\n";
    std::exit(0);
  }

  if (cfg.stats_every_sec <= 0) cfg.stats_every_sec = 1;
  if (cfg.snaplen <= 0) cfg.snaplen = 65535;

  if (cfg.top_talkers < 0) cfg.top_talkers = 0;
  if (cfg.top_flows < 0) cfg.top_flows = 0;
  if (cfg.top_hosts < 0) cfg.top_hosts = 0;

  return cfg;
}

} // namespace npa
