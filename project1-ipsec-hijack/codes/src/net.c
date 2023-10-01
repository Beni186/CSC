#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/ip.h>
#include "net.h"
#include "transport.h"
#include "esp.h"
int id = 0;
uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
    uint32_t now = 0;
    iphdr.check = 0;
    uint16_t*pos = (uint16_t*) &iphdr;
    for(int i = 0; i<10 ; i++)
    {
        now += ntohs(*(pos+i));
    }
    uint32_t over = now/65536;
    now = now %65536;
    now += over;
    uint16_t ans = now;
    ans = ~ans;
    return ans;
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer

    //get the length of the header and payload
    
    struct iphdr* iph;
    iph = (struct iphdr*) pkt;
    unsigned int hl = iph -> ihl * 4;
    pkt_len = ntohs(iph -> tot_len);
    self -> pro = iph->protocol;
    memcpy(&(self->ip4hdr),iph,sizeof(struct iphdr));
    //get the length of the header and payload
    int tot_len = pkt_len-hl;
    struct in_addr s,d;
    self -> plen = tot_len;
    s.s_addr = iph->saddr;
    d.s_addr = iph->daddr;
    strcpy(self->src_ip,inet_ntoa(s));
    strcpy(self->dst_ip,inet_ntoa(d));
    /*self -> plen = ntohs(iph -> tot_len)-sizeof(struct iphdr);
    uint32_t sa = iph -> saddr;
    uint32_t da = iph -> daddr;
    uint8_t* s = (uint8_t*)&sa;
    uint8_t* d = (uint8_t*)&da;
    self -> src_ip = s;
    self -> dst_ip = d;*/
    return pkt + hl;
}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)
    self -> ip4hdr.tot_len = htons(sizeof(struct iphdr))+htons(self->plen);
    self -> ip4hdr.id = htons(ntohs(self -> ip4hdr.id)+1);
    
    if(strcmp(self->x_src_ip, self->dst_ip) == 0){
        uint32_t temp = self->ip4hdr.saddr;
        self->ip4hdr.saddr = self->ip4hdr.daddr;
        self->ip4hdr.daddr = temp;
    }
    /*else{
        uint32_t temp = self->ip4hdr.saddr;
        self->ip4hdr.saddr = self->ip4hdr.daddr;
        self->ip4hdr.daddr = temp;

        self -> ip4hdr.id = htons(ntohs(id)+1);
    }*/
    self -> ip4hdr.check = htons(cal_ipv4_cksm( self -> ip4hdr));

    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }
    self->id = 0;
    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}
