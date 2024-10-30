#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <cstdio>
#include "CodeFinals.hpp"



//@@@@@@@@@@@@@@@@@@@@ temporary?
inline [[maybe_unused]] std::string maskZero(const std::string& str) {
    size_t n = str.length();
    std::string res(255 - n, '\0');
    return res + str;
}


//@@@@@@@@@@@@@@@@@@@@ temporary
inline void printVector(const std::vector<uint8_t>& vec) {
    int index = 0;
    for (auto var : vec) {
        if (var != 0) {
            // הדפסת האינדקס
            printf("[%d] = ", index);

            // הדפסה עשרונית
            std::cout << std::dec << static_cast<int>(var) << " : ";

            // הדפסה הקסדצימלית
            std::cout << std::hex << static_cast<int>(var & 0xFF) << " : ";

            // הדפסת הערך המקורי
            std::cout << static_cast<int>(var) << std::endl;
        }
        index++;
    }
}


inline std::vector<uint8_t> strToBytes(const std::string& idStr) {
    std::vector<uint8_t> bytes;
    for (char i : idStr)
        bytes.push_back(i);
    return bytes;
}

inline void pushUintToBuffer(std::vector<uint8_t>& buffer, uint32_t value, size_t byteSize) {
    for (size_t i = byteSize - 1; i >= 0; --i) {
        buffer.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

inline std::vector<uint8_t> getSubVector(const std::vector<uint8_t>& vec, size_t start, size_t end) {
    return std::vector<uint8_t>(vec.begin() + start, vec.begin() + end);
}