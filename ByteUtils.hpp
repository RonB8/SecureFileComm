#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <cstdio>
#include "CodeFinals.hpp"



inline std::vector<uint8_t> strToBytes(const std::string& idStr) {
    std::vector<uint8_t> bytes;
    for (char i : idStr)
        bytes.push_back(i);
    return bytes;
}

//As little endian
inline void pushUintToBuffer(std::vector<uint8_t>& buffer, uint32_t value, size_t byteSize) {
    if (byteSize == 0) {
        std::cerr << "Error in pushUintToBuffer. Byte size must be poisitive.";
    }
    else {
        for (int i = 0; i < byteSize; i++) {
            buffer.push_back(static_cast<uint8_t>(value >> (8 * i)));
        }
    }
}

inline std::vector<uint8_t> getSubVector(const std::vector<uint8_t>& vec, size_t start, size_t end) {
    return std::vector<uint8_t>(vec.begin() + start, vec.begin() + end);
}
