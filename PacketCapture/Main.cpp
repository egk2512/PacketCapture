#include <iostream>
#include <pcap.h>
#include <vector>
#include <array>

#include "Level2.h"

void Hello(){
  std::cout << "Welcum to the club buddy";
}

struct Packet {
    Level2* level2;

    Packet(Level2* level2) : level2{level2}{}
};

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    std::vector<u_char> data{ packet, packet + header->len };
    Level2Type type = define_level2_type(data);

    Level2* obj = nullptr;
    if (type == Level2Type::Ethernet) {
        Ethernet temp(data);
        obj = &temp;
    }
    else {
        std::cout << "Error: undefined level 2 type\n";
        return;
    }

    Packet final_packet(obj);
    final_packet.level2->print_info();

    return;
}

//Hello

int main(int argc, char* argv[])
{ 
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    pcap_if_t* interfaces = nullptr;
    if (pcap_findalldevs(&interfaces, errbuf) == -1 || interfaces == nullptr) {
        std::cout << "Error: couldnt find device - " << errbuf << std::endl;
        return -1;
    }

    std::cout << "Interfaces:" << std::endl;
    pcap_if_t* temp = interfaces;
    int counter = 0;
    for (pcap_if_t* temp = interfaces; temp != nullptr; temp = temp->next) {
        std::cout << "\t" << counter <<  ":" << temp->name << " aka: " << temp->description << std::endl;
        counter += 1;
    }
    
    std::cout << "Which interface do you want to use? (enter number): ";
    std::cin >> counter;
    for (int i = 0; i < counter; ++i) {
        interfaces = interfaces->next;
    }
    std::cout << "Opening interface: \n" << interfaces->name << std::endl;
    pcap_t* handle = pcap_open_live(interfaces->name, BUFSIZ, 1, 10000, errbuf);
    pcap_freealldevs(interfaces);
    if (handle == NULL) {
        std::cout << "Error: couldnt open device - " << errbuf << std::endl;
        return 1;
    }

    struct pcap_pkthdr header;
    const u_char* packet;
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}

// Test
