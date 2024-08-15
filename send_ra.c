#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <linux/if_ether.h>

#define MAC_SIZ 6
#define IP6_SIZ 16
#define MAX_PACKET_SIZE 1280
/*
struct nd_opt_mtu {
    uint8_t nd_opt_type;
    uint8_t nd_opt_len;
    uint16_t nd_opt_reserved;
    uint32_t nd_opt_mtu;
};
*/

char icmp6_ra_buffer[1024];

struct ndp_ra_pkt {
    struct icmp6_hdr icmp6_hdr;
    //unsigned char target_ip[IP6_SIZ];
    struct nd_opt_mtu option_mtu;
    /*unsigned char option_smac[IP6_SIZ];
    uint8_t cur_hop_limit;
    uint8_t flags;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retrans_timer;
    */
};

void error_exit(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

void usage() {
    fprintf(stdout, "Usage: send_ra <device>\n");
}

static inline int ioctl_ifreq(char *dev, int fd, int cmd, struct ifreq *ifr) {
    memset(ifr, 0, sizeof(struct ifreq));
    strcpy(ifr->ifr_name, dev);
    if (ioctl(fd, cmd, ifr) < 0) {
        fprintf(stderr, "failed to call ioctl cmd %d\n", cmd);
        return -1;
    }
    return 0;
}

static int send_ndp_ra(char *dev) {
    int ret = -1, byte_sent, fd;
    struct ifreq ifr_if = {0};
    struct sockaddr_in6 target;
    struct ndp_ra_pkt pkt = {0};
    char buffer[MAX_PACKET_SIZE];

    /* -------- prepare socket -------- */
    if ((fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
        fprintf(stderr, "cannot open socket\n");
        return ret;
    }
    strcpy(ifr_if.ifr_name, dev);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr_if, sizeof(ifr_if)) < 0) {
        fprintf(stderr, "cannot bind to dev %s\n", dev);
        goto err_ret;
    }

    /* -------- get target address -------- */
    memset(&target, 0, sizeof(target));
    target.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "ff02::1", &target.sin6_addr);
    target.sin6_port = htons(IPPROTO_ICMPV6);
    
    /* -------- get device index, MAC -------- 
    target->sin6_scope_id = if_nametoindex(dev);
    if (ioctl_ifreq(dev, fd, SIOCGIFHWADDR, &ifr_mac) < 0) {
        fprintf(stderr, "err in ioctl_ifreq()\n");
        goto err_ret;
    }*/

    /* -------- fill NDP packet -------- 
    pkt.icmp6_hdr.icmp6_type = 134;  //
    pkt.icmp6_hdr.icmp6_code = 0;
    pkt.icmp6_hdr.icmp6_cksum = 0;
    pkt.cur_hop_limit = 64;
    pkt.flags = 0;
    pkt.reachable_time = htonl(3600);
    pkt.retrans_timer = htonl(1000);
    memcpy(pkt.target_ip, target->sin6_addr.s6_addr, IP6_SIZ);
    pkt.option_mtu.nd_opt_mtu_type = 5;  // 1
    pkt.option_mtu.nd_opt_mtu_len = 1;  // length in units of 8 octets
    pkt.option_mtu.nd_opt_mtu_reserved = 0;
    memcpy(pkt.option_smac, ifr_mac.ifr_hwaddr.sa_data, MAC_SIZ);*/
    
    void fill_icmp6_header(uint8_t *buffer, uint8_t type, uint8_t code, uint16_t checksum, uint32_t data_length) {
        struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)buffer;
        icmp6_hdr->icmp6_type = type;
        icmp6_hdr->icmp6_code = code;
        icmp6_hdr->icmp6_cksum = checksum;
        //icmp6_hdr->icmp6_dataun.un_data16[0] = htons(data_length);
}

    uint16_t pseudo_header_checksum = 0;
    uint16_t checksum_placeholder = 0;
    fill_icmp6_header(icmp6_ra_buffer, 134, 0, checksum_placeholder, 0);
    //unsigned short checksum = 0;
    
    //pkt.icmp6_hdr.icmp6_cksum = thons(0*1234)
    /* -------- send packet -------- */
    memcpy(buffer, &pkt, sizeof(pkt));
    byte_sent = sendto(fd, icmp6_ra_buffer, sizeof(icmp6_ra_buffer), 0, (struct sockaddr *)&target, sizeof(target));
    if (byte_sent < 0) {
        fprintf(stderr, "err in sendto()\n");
        goto err_ret;
    }

    ret = 0;
    fprintf(stdout, "successfully sent NDP Router Advertisement (RA), sent bytes: %d\n", byte_sent);
err_ret:
    close(fd);
    return ret;
}

int main(int argc, char **argv) {
    struct sockaddr_storage target_addr = {0};

    if (argc < 2) {
        usage();
        return -1;
    }

    /*if (inet_pton(AF_INET, argv[1], &((struct sockaddr_in *)&target_addr)->sin_addr) > 0) {
        fprintf(stderr, "not support IPv4 address, NDP is for IPv6 only\n");
        return -1;
    } else if (inet_pton(AF_INET6, argv[1], &((struct sockaddr_in6 *)&target_addr)->sin6_addr) > 0)
        target_addr.ss_family = AF_INET6;
    else {
        fprintf(stderr, "target IP address %s is not valid\n", argv[1]);
        return -1;
    }*/

    if (send_ndp_ra( argv[1]) < 0) {
        fprintf(stderr, "failed to send pkt for neigh request\n");
        return -1;
    }

    return 0;
}
