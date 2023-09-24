#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        // Skip non-IP packets
        return;
    }

    ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    if (ip_header->ip_p != IPPROTO_TCP) {
        // Skip non-TCP packets
        return;
    }

    tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));

    // Extract and print Ethernet source and destination MAC addresses
    printf("Ethernet Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1],
           eth_header->ether_shost[2], eth_header->ether_shost[3],
           eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Ethernet Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1],
           eth_header->ether_dhost[2], eth_header->ether_dhost[3],
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    // Extract and print source and destination IP addresses
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

    // Extract and print source and destination ports
    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));

    // Extract and print message (data)
    int data_length = pkthdr->len - (ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
    if (data_length > 0) {
        printf("Message Data: ");
        for (int i = 0; i < data_length; i++) {
            printf("%02X ", packet[ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2) + i]);
        }
        printf("\n");
    }

    printf("\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open live pcap session on the desired network interface (change "enp0s3" to your interface name)
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface: %s\n", errbuf);
        return 1;
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the pcap session when done
    pcap_close(handle);

    return 0;
}
