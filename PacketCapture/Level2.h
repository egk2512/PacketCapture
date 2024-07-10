#pragma once
#include <iostream>
#include <vector>
#include <array>
#include <pcap.h>

enum class Level2Type {
    Undefined = 0,
    Ethernet = 1
};

Level2Type define_level2_type(const std::vector<u_char>& data) {
    if (data[12] > 0x06) {
        return Level2Type::Ethernet;
    }
    return Level2Type::Undefined;
}

struct MAC {
    std::array<u_char, 6> data{};

    MAC(std::array<u_char, 14> arr, size_t start) {
        for (int i = 0; i < 6; ++i) {
            data[i] = arr.at(i + start);
        }
    }

    void print() {
        for (auto const& elem : data) {
            std::cout << std::hex << int(elem) << " ";
        }
    }
};

interface Level2 {
    virtual ~Level2() = default;

    virtual MAC get_sender_mac() = 0;
    virtual MAC get_target_mac() = 0;

    virtual void print_info() = 0;
};

struct Ethernet : Level2 {
    std::array<u_char, 14> data{};

    Ethernet(const std::vector<u_char>& vec) {
        std::copy(vec.begin(), vec.begin() + 14, data.begin());
    }

    MAC get_sender_mac() {
        MAC sender_mac(data, 6);
        return sender_mac;
    }

    MAC get_target_mac() {
        MAC target_mac(data, 0);
        return target_mac;
    }

    void print_info() {
        std::cout << "\n\nInformation:";

        std::cout << "\n\tEthernet 2: ";
        for (auto const& elem : data) {
            std::cout << std::hex << int(elem) << " ";
        }

        std::cout << "\n\tSender MAC: ";
        get_sender_mac().print();

        std::cout << "\n\tTarget MAC: ";
        get_target_mac().print();
    }
};




