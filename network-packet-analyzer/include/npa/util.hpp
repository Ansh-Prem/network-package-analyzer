#pragma once
#include <cstdint>
#include <string>

namespace npa {

uint16_t read_be16(const uint8_t* p);
uint32_t read_be32(const uint8_t* p);
std::string ipv4_to_string(uint32_t be_addr);

} // namespace npa
