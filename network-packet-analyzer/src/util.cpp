#include "npa/util.hpp"
#include <sstream>

namespace npa {

uint16_t read_be16(const uint8_t* p) {
  return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

uint32_t read_be32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

// Input is big-endian IPv4 address as uint32_t.
std::string ipv4_to_string(uint32_t be_addr) {
  uint8_t a = (be_addr >> 24) & 0xFF;
  uint8_t b = (be_addr >> 16) & 0xFF;
  uint8_t c = (be_addr >> 8) & 0xFF;
  uint8_t d = (be_addr) & 0xFF;

  std::ostringstream oss;
  oss << int(a) << "." << int(b) << "." << int(c) << "." << int(d);
  return oss.str();
}

} // namespace npa
