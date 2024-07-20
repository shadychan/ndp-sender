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

#define MAC_SIZ 6
#define IP6_SIZ 16

/* 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|   Type = 135  |     Code      |           Checksum            |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|                           Reserved                            |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|                                                               |
 *|                             Target                            |
 *|                          IPv6 Address                         |
 *|                                                               |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|                            Options                            |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/**
 * @brief
 *    NDP neighbor solicitation packet structure.
 *
 * @note
 *    Neighbor Solicitation, one of the types of NDP (Neighbor Discovery Protocol),
 *    is to determine link-layer address of a neighbor, or to verify if a neighbor
 *    is still reachable.
 *    NDP is used for IPv6 address and based on ICMPv6 protocol. NS was defined to
 *    be Type=135 in ICMPv6 header.
 * @see
 *    https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol
 */
struct ndp_ns_pkt {
    struct icmp6_hdr icmp6_hdr;
    unsigned char target_ip[IP6_SIZ];
    struct nd_opt_hdr option_hdr;
    unsigned char option_smac[IP6_SIZ];
};

void usage() {
    fprintf(stdout, "Usage: send_ns <target_ipv6> <device>\n");
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

static int send_ndp_ns(struct sockaddr_in6 *target, char *dev) {
    int ret = -1, byte_sent, fd;
    struct ifreq ifr_if = {0}, ifr_mac;
    struct ndp_ns_pkt pkt = {0};

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

    /* -------- get device index, MAC -------- */
    target->sin6_scope_id = if_nametoindex(dev);
    if (ioctl_ifreq(dev, fd, SIOCGIFHWADDR, &ifr_mac) < 0) {
        fprintf(stderr, "err in ioctl_ifreq()\n");
        goto err_ret;
    }

    /* -------- fill NDP packet -------- */
    pkt.icmp6_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;  // 135
    pkt.icmp6_hdr.icmp6_code = 0;
    memcpy(pkt.target_ip, target->sin6_addr.s6_addr, IP6_SIZ);
    pkt.option_hdr.nd_opt_type = ND_OPT_SOURCE_LINKADDR;  // 1
    pkt.option_hdr.nd_opt_len = 1;  // length in units of 8 octets
    memcpy(pkt.option_smac, ifr_mac.ifr_hwaddr.sa_data, MAC_SIZ);

    /* -------- send packet -------- */
    byte_sent = sendto(fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)target, sizeof(*target));
    if (byte_sent < 0) {
        fprintf(stderr, "err in sendto()\n");
        goto err_ret;
    }

    ret = 0;
    fprintf(stdout, "successfully sent NDP Neighbor Solicitation (NS), sent bytes: %d\n", byte_sent);
err_ret:
    close(fd);
    return ret;
}

int main(int argc, char **argv) {
    struct sockaddr_storage target_addr = {0};

    if (argc < 3) {
        usage();
        return -1;
    }

    if (inet_pton(AF_INET, argv[1], &((struct sockaddr_in *)&target_addr)->sin_addr) > 0) {
        fprintf(stderr, "not support IPv4 address, NDP is for IPv6 only\n");
        return -1;
    } else if (inet_pton(AF_INET6, argv[1], &((struct sockaddr_in6 *)&target_addr)->sin6_addr) > 0)
        target_addr.ss_family = AF_INET6;
    else {
        fprintf(stderr, "target IP address %s is not valid\n", argv[1]);
        return -1;
    }

    if (send_ndp_ns((struct sockaddr_in6 *)&target_addr, argv[2]) < 0) {
        fprintf(stderr, "failed to send pkt for neigh request\n");
        return -1;
    }

    return 0;
}