#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr {
    u_int8_t  ether_dhost[ETHER_ADDR_LEN]; /* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN]; /* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_tcp_hdr {
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;         /* sequence number */
    u_int32_t th_ack;         /* acknowledgement number */
};

struct ip_hdr {
    u_char ip_vhl;       /* version << 4 | header length >> 2 */
    u_char ip_tos;       /* type of service */
    u_short ip_len;      /* total length */
    u_short ip_id;       /* identification */
    u_short ip_off;      /* fragment offset field */
    u_char ip_ttl;       /* time to live */
    u_char ip_p;         /* protocol */
    u_short ip_sum;      /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

void print_mac(u_int8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_port(u_int16_t p) {
    printf("%u", ntohs(p));
}

void print_ip(struct in_addr *ip) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip, ip_str, INET_ADDRSTRLEN);
    printf("%s", ip_str);
}

void print_payload(const u_char *payload, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", payload[i]);
    }
}

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
        struct ip_hdr *ip_h = (struct ip_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
        struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct ip_hdr));
        
        if (ip_h->ip_p != IPPROTO_TCP) {
            continue;
        }
        
        printf("src mac - ");
        print_mac(eth_hdr->ether_shost);
        printf("\n");
        printf("dst mac - ");
        print_mac(eth_hdr->ether_dhost);
        printf("\n");

        printf("src ip - ");
        print_ip(&ip_h->ip_src);
        printf("\n");
        printf("dst ip - ");
        print_ip(&ip_h->ip_dst);
        printf("\n");


        printf("src port - ");
        print_port(tcp_hdr->th_sport);
        printf("\n");
        printf("dst port - ");
        print_port(tcp_hdr->th_dport);
        printf("\n");
        
        const u_char *payload = (packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct libnet_tcp_hdr));
        printf("payload - ");
        print_payload(payload, 10);
        printf("\n==============================\n");
    }

    pcap_close(pcap);
}

