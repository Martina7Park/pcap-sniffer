#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Ethernet Header
    struct ether_header *eth = (struct ether_header *)packet;

    printf("\nEthernet 헤더\n");
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    // IP Header
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
    if (ip_hdr->ip_p != IPPROTO_TCP) return; // TCP만 대상

    int ip_header_len = ip_hdr->ip_hl * 4;

    printf("\nIP 헤더\n");
    printf("Src IP: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("Dst IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

    // TCP Header
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
    int tcp_header_len = tcp_hdr->doff * 4;

    printf("\nTCP 헤더\n");
    printf("Src Port: %d\n", ntohs(tcp_hdr->source));
    printf("Dst Port: %d\n", ntohs(tcp_hdr->dest));

    // Payload
    int total_headers = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - total_headers;

    if (payload_len > 0) {
        const u_char *payload = packet + total_headers;
        printf("\n===== [Payload] (%d bytes) =====\n", payload_len);
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
        fprintf(stderr, "실패: %s\n", errbuf);
        return 1;
    }

    printf("대기중\n");
    pcap_loop(handle, 0, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
