#pragma once
#include <cstdint>
#include <string>

namespace npa {

enum class L4Proto { TCP, UDP, OTHER };

struct PacketInfo {
  // L3/L4 summary
  bool ipv4 = false;
  L4Proto l4 = L4Proto::OTHER;

  std::string src_ip;
  std::string dst_ip;

  uint16_t src_port = 0;
  uint16_t dst_port = 0;

  uint16_t ip_total_len = 0;
  uint8_t  ip_ttl = 0;

  // HTTP extraction (plaintext HTTP only)
  bool http = false;
  std::string http_method;
  std::string http_uri;
  std::string http_host;

  // Raw capture
  uint32_t caplen = 0;
  uint32_t wirelen = 0;
};

} // namespace npa
