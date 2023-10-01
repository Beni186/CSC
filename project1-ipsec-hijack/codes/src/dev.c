#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>

#include "dev.h"
#include "net.h"
#include "esp.h"
#include "replay.h"
#include "transport.h"
uint8_t* need;
inline static int get_ifr_mtu(struct ifreq *ifr)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCGIFMTU, ifr) < 0) {
        perror("ioctl()");
        close(fd);
        exit(EXIT_FAILURE);
    }
    return ifr->ifr_mtu;
}

inline static struct sockaddr_ll init_addr(char *name)
{
    struct sockaddr_ll addr;
    bzero(&addr, sizeof(addr));

    // [TODO]: Fill up struct sockaddr_ll addr which will be used to bind in func set_sock_fd
    addr.sll_protocol = 0x0800;
    addr.sll_ifindex = if_nametoindex(name);
    printf("%d\n", addr.sll_ifindex);
    if (addr.sll_ifindex == 0) {
        perror("if_nameindex()");
        exit(EXIT_FAILURE);
    }

    return addr;
}

inline static int set_sock_fd(struct sockaddr_ll dev)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    bind(fd, (struct sockaddr *)&dev, sizeof(dev));

    return fd;
} 

void fmt_frame(Dev *self, Net net, Esp esp, Txp txp)
{
    // [TODO]: store the whole frame into self->frame
    // and store the length of the frame into self->framelen
    if(txp.plen != 0)  
    {
        need = (uint8_t* )malloc(LINKHDRLEN * sizeof(uint8_t));
        memcpy(need,self->frame,LINKHDRLEN);
    }
    else
    {
        memcpy(self->frame,need,LINKHDRLEN);
    }
    int n =  LINKHDRLEN;
    memcpy(self->frame+n,&net.ip4hdr,sizeof(struct iphdr));
    n += sizeof(struct iphdr);
    memcpy(self->frame+n,&esp.hdr,sizeof(struct esp_header));
    n += sizeof(struct esp_header);
    memcpy(self->frame+n,&txp.thdr,sizeof(struct tcphdr));
    n += sizeof(struct tcphdr);
    memcpy(self->frame+n,txp.pl,txp.plen);
    n += txp.plen;
    memcpy(self->frame+n,esp.pad,esp.tlr.pad_len);
    n += esp.tlr.pad_len;
    memcpy(self->frame+n,&esp.tlr,sizeof(struct esp_trailer));
    n += sizeof(struct esp_trailer);
    memcpy(self->frame+n,esp.auth,esp.authlen);
    n += esp.authlen;
    self->framelen = n;
}

ssize_t tx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);
    // cool 
    uint8_t* buff;
    struct sockaddr_ll  a = self->addr;
    buff = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    nb = recvfrom(self->fd, buff, self->mtu,
                  0, (struct sockaddr *)&a, &addrlen);
    struct tcphdr* t;
    t = (struct tpdhr*)(buff+LINKHDRLEN+sizeof(struct iphdr));
    while((t->ack) != 1)
    {
        nb = recvfrom(self->fd, buff, self->mtu,
                  0, (struct sockaddr *)&a, &addrlen);
        t = (struct tpdhr*)(buff+LINKHDRLEN+sizeof(struct iphdr));
    }
    //
    nb = sendto(self->fd, self->frame, self->framelen,
                0, (struct sockaddr *)&self->addr, addrlen);

    if (nb <= 0) perror("sendto()");

    return nb;
}

ssize_t rx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);
    nb = recvfrom(self->fd, self->frame, self->mtu,
                  0, (struct sockaddr *)&self->addr, &addrlen);
    if (nb <= 0)
        perror("recvfrom()");

    return nb;
}

void init_dev(Dev *self, char *dev_name)
{

    if (!self || !dev_name || strlen(dev_name) + 1 > IFNAMSIZ) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    self->mtu = get_ifr_mtu(&ifr);

    self->addr = init_addr(dev_name);
    self->fd = set_sock_fd(self->addr);

    self->frame = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    self->framelen = 0;

    self->fmt_frame = fmt_frame;
    self->tx_frame = tx_frame;
    self->rx_frame = rx_frame;

    self->linkhdr = (uint8_t *)malloc(LINKHDRLEN);
}
