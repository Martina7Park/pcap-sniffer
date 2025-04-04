#include "myheader.h"

// 패킷 처리 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *)packet;

    printf("\n===== [Ethernet Header] =====\n");
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    int ip_header_len = ip_hdr->ip_hl * 4;

    printf("\n===== [IP Header] =====\n");
    printf("Src IP: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("Dst IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
    int tcp_header_len = tcp_hdr->doff * 4;

    printf("\n===== [TCP Header] =====\n");
    printf("Src Port: %d\n", ntohs(tcp_hdr->source));
    printf("Dst Port: %d\n", ntohs(tcp_hdr->dest));

    int total_headers = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - total_headers;

    if (payload_len > 0) {
        const u_char *payload = packet + total_headers;

        printf("\n===== [Payload - 최대 32바이트] =====\n");
        for (int i = 0; i < payload_len && i < 32; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *dev = "eth0"; 

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "장치 열기 실패: %s\n", errbuf);
        return 1;
    }

    printf("=== TCP 패킷 수신 대기 중... ===\n");
    pcap_loop(handle, 0, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
