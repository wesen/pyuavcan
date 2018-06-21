#include <stdint.h>

static const uint64_t MASK = 0xFFFFFFFFFFFFFFFF;
static const uint64_t POLY = 0x42F0E1EBA9EA3693;

uint64_t crc64(const char* data, uint32_t len, uint64_t initial);
uint64_t finalize(uint64_t crc);

uint64_t crc64(const char* data, uint32_t len, uint64_t initial) {
    uint64_t crc = initial;

    for (uint32_t i = 0; i < len; i++) {
        uint64_t d = (data[i] & 0xFFu);
        crc ^= (d << 56) & MASK;
        for (int j = 0; j < 8; j++) {
            if (crc & (1llu << 63)) {
                crc = ((crc << 1) & MASK) ^ POLY;
            } else {
                crc <<= 1;
            }
        }
    }

    return crc;
}

uint64_t finalize(uint64_t crc) {
    return (crc & MASK) ^ MASK;
}
