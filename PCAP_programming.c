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
    char *data;

    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        // 이더넷 프레임 타입이 IP가 아닌 경우 패스
        return;
    }

    ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    if (ip_header->ip_p != IPPROTO_TCP) {
        // IP 패킷의 프로토콜이 TCP가 아닌 경우 패스
        return;
    }

    tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
    data = (char *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));

    // 이더넷 소스 및 대상 MAC 주소 출력
    printf("Ethernet 소스 MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1],
           eth_header->ether_shost[2], eth_header->ether_shost[3],
           eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Ethernet 대상 MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1],
           eth_header->ether_dhost[2], eth_header->ether_dhost[3],
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    // 소스 및 대상 IP 주소 출력
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

    // 소스 및 대상 포트 출력
    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));

    // 메시지 데이터 출력
    printf("Message: ");
    for (int i = 0; i < pkthdr->len - (ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2)); i++) {
        printf("%c", data[i]);
    }
    printf("\n");

    printf("\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 원하는 네트워크 인터페이스에 대한 라이브 pcap 세션 열기 (인터페이스 이름을 변경하세요)
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "인터페이스 열기 오류: %s\n", errbuf);
        return 1;
    }

    // 패킷 캡처 시작
    pcap_loop(handle, 0, packet_handler, NULL);

    // 사용이 끝난 pcap 세션 닫기
    pcap_close(handle);

    return 0;
}
