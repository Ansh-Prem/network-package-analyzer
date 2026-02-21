#pragma once
#include "npa/packet.hpp"
#include <cstdint>
#include <optional>

namespace npa {

// Parse Ethernet + IPv4 + TCP/UDP.
// For TCP: also tries to extract plaintext HTTP request Host header (no reassembly).
std::optional<PacketInfo> parse_packet(const uint8_t* data, uint32_t caplen, uint32_t wirelen);

} // namespace npa
