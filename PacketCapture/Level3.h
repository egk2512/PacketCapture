#pragma once
#include <iostream>
#include <vector>
#include <array>
#include <pcap.h>

enum class Level3Type {
    Undefined = 0,
    Ethernet = 1
};

Level3Type define_level2_type(std::vector<u_char> data) {}

struct IPv4 {
    std::array<u_char, 4> data{};

    IPv4(std::array<u_char, 14> arr, size_t start) {}

    void print() {
        for (auto const& elem : data) {
            std::cout << std::hex << int(elem) << " ";
        }
    }
};