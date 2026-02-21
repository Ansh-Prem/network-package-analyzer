#include "npa/parser.hpp"
#include "npa/util.hpp"
#include <algorithm>
#include <cctype>
#include <string_view>

namespace npa {

static constexpr uint32_t ETH_HDR = 14;
static constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;

static bool starts_with(std::string_view s, std::string_view p) {
  return s.size() >= p.size() && s.substr(0, p.size()) == p;
}

static std::string trim(std::string s) {
  auto not_space = [](unsigned char c){ return !std::isspace(c); };
  while (!s.empty() && !not_space((unsigned char)s.front())) s.erase(s.begin());
  while (!s.empty() && !not_space((unsigned char)s.back())) s.pop_back();
  return s;
}

static bool ieq_prefix(std::string_view s, std::string_view p) {
  if (s.size() < p.size()) return false;
  for (size_t i = 0; i < p.size(); i++) {
    if (std::tolower((unsigned char)s[i]) != std::tolower((unsigned char)p[i])) return false;
  }
  return true;
}

// Parse HTTP request line + Host header from TCP payload (best-effort, no reassembly).
static void try_parse_http(PacketInfo& info, const uint8_t* payload, uint32_t payload_len) {
  if (!payload || payload_len < 16) return;

  // Limit scan to avoid huge payload work
  uint32_t n = std::min<uint32_t>(payload_len, 4096);
  std::string_view sv(reinterpret_cast<const char*>(payload), n);

  // Common methods
  const char* methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH "};
  bool is_http = false;
  std::string method;

  for (auto m : methods) {
    if (starts_with(sv, m)) {
      is_http = true;
      method = std::string(m);
      method.pop_back(); // remove trailing space
      break;
    }
  }
  if (!is_http) return;

  // Request line: METHOD SP URI SP HTTP/...
  auto line_end = sv.find("\r\n");
  if (line_end == std::string_view::npos) return;

  std::string_view line = sv.substr(0, line_end);
  // find first and second spaces
  size_t sp1 = line.find(' ');
  if (sp1 == std::string_view::npos) return;
  size_t sp2 = line.find(' ', sp1 + 1);
  if (sp2 == std::string_view::npos) return;

  std::string uri(line.substr(sp1 + 1, sp2 - (sp1 + 1)));

  // Headers start after CRLF
  std::string host;
  size_t pos = line_end + 2;

  while (pos < sv.size()) {
    size_t next = sv.find("\r\n", pos);
    if (next == std::string_view::npos) break;
    if (next == pos) break; // blank line -> end headers

    std::string_view hline = sv.substr(pos, next - pos);
    // Host: example.com
    if (ieq_prefix(hline, "Host:")) {
      std::string v(hline.substr(5));
      host = trim(v);
      break;
    }
    pos = next + 2;
  }

  info.http = true;
  info.http_method = method;
  info.http_uri = uri;
  info.http_host = host;
}

std::optional<PacketInfo> parse_packet(const uint8_t* data, uint32_t caplen, uint32_t wirelen) {
  PacketInfo info;
  info.caplen = caplen;
  info.wirelen = wirelen;

  if (!data || caplen < ETH_HDR) return std::nullopt;

  uint16_t etherType = read_be16(data + 12);
  if (etherType != ETHERTYPE_IPV4) return std::nullopt;

  const uint8_t* ip = data + ETH_HDR;
  uint32_t ip_avail = caplen - ETH_HDR;
  if (ip_avail < 20) return std::nullopt;

  uint8_t ver_ihl = ip[0];
  uint8_t ver = ver_ihl >> 4;
  uint8_t ihl = (ver_ihl & 0x0F) * 4;
  if (ver != 4 || ihl < 20) return std::nullopt;
  if (ip_avail < ihl) return std::nullopt;

  info.ipv4 = true;
  info.ip_total_len = read_be16(ip + 2);
  info.ip_ttl = ip[8];
  uint8_t proto = ip[9];

  uint32_t src_be = read_be32(ip + 12);
  uint32_t dst_be = read_be32(ip + 16);
  info.src_ip = ipv4_to_string(src_be);
  info.dst_ip = ipv4_to_string(dst_be);

  const uint8_t* l4 = ip + ihl;
  uint32_t l4_avail = ip_avail - ihl;

  if (proto == 6) { // TCP
    if (l4_avail < 20) return info;
    info.l4 = L4Proto::TCP;

    info.src_port = read_be16(l4 + 0);
    info.dst_port = read_be16(l4 + 2);

    uint8_t data_offset = (l4[12] >> 4) * 4;
    if (data_offset < 20 || l4_avail < data_offset) return info;

    const uint8_t* payload = l4 + data_offset;
    uint32_t payload_len = l4_avail - data_offset;

    // Only attempt HTTP on typical HTTP ports OR if payload clearly looks like HTTP.
    // (Port check reduces false positives.)
    if (info.src_port == 80 || info.dst_port == 80 || info.src_port == 8080 || info.dst_port == 8080) {
      try_parse_http(info, payload, payload_len);
    } else {
      // Sometimes HTTP runs on non-standard ports in labs; lightweight heuristic:
      try_parse_http(info, payload, payload_len);
      if (!info.http) {
        info.http_method.clear();
        info.http_uri.clear();
        info.http_host.clear();
      }
    }

    return info;

  } else if (proto == 17) { // UDP
    if (l4_avail < 8) return info;
    info.l4 = L4Proto::UDP;
    info.src_port = read_be16(l4 + 0);
    info.dst_port = read_be16(l4 + 2);
    return info;

  } else {
    info.l4 = L4Proto::OTHER;
    return info;
  }
}

} // namespace npa
