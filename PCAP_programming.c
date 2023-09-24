#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <openssl/ssl.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    const u_char *ssl_data;

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
    ssl_data = packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2);

    // SSL/TLS 데이터로부터 SSL/TLS 세션 생성
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ssl_ctx);

    // SSL/TLS 데이터를 읽고 해석
    SSL_set_fd(ssl, fileno(stdout)); // 출력을 표준 출력으로 설정 (또는 원하는 파일 디스크립터로 설정)
    SSL_write(ssl, ssl_data, pkthdr->len - (ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2)));
    SSL_read(ssl, ssl_data, pkthdr->len - (ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2)));

    // SSL/TLS 데이터 출력 (디코딩 성공한 경우)
    if (SSL_get_error(ssl, 0) == SSL_ERROR_NONE) {
        printf("Decrypted Message: %s\n", ssl_data);
    } else {
        // SSL/TLS 디코딩에 실패한 경우 바이트 데이터 출력
        printf("Message (Byte Data): ");
        for (int i = 0; i < pkthdr->len - (ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2)); i++) {
            printf("%02X ", ssl_data[i]);
        }
        printf("\n");
    }

    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);

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
