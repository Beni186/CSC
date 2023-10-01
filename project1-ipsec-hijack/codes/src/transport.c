#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "net.h"
#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
bool sf = true;
/* set tcp checksum: given IP header and tcp segment */
uint16_t compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload,unsigned short tcpLen) {
    uint32_t sum = 0;
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header 
    //the source ip
    sum += (ntohl(pIph->saddr)>>16)&0xFFFF;
    sum += (ntohl(pIph->saddr))&0xFFFF;
    //the dest ip
    sum += (ntohl(pIph->daddr)>>16)&0xFFFF;
    sum += (ntohl(pIph->daddr))&0xFFFF;
    //protocol and reserved: 6W
    sum += (IPPROTO_TCP);
    //the length
    sum += (tcpLen);
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    uint32_t rs = 0;
    while (tcpLen > 1) {
        uint32_t temp = ntohs(* ipPayload);
        sum += temp;
        rs += temp;
        (ipPayload++);
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        uint32_t temp = (*ipPayload)&htons(0xFF00);
        sum += ntohs(temp);
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    return (unsigned short)sum;
}
uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    uint8_t* all = (uint8_t*)malloc(plen+sizeof(struct tcphdr) * sizeof(uint8_t));
    memcpy(all,&tcphdr,sizeof(struct tcphdr));
    memcpy(all+sizeof(struct tcphdr),pl,plen);
    return compute_tcp_checksum(&iphdr, (unsigned short *)all,plen+sizeof(tcphdr));

}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len,bool mode)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP
    int hl = 2+2+4+4+2+2+2+2;
    struct tcphdr* th = (struct tcphdr*) segm;
    int len = segm_len-20;
    self->plen = len;
    self->out_len = len;
    uint32_t pre_ack =self->thdr.th_ack;
    memcpy(&(self->thdr),th,sizeof(struct tcphdr));
    if(!sf)
    {
        uint32_t temp;
        if (pre_ack == self->thdr.th_seq && strcmp(net->x_src_ip, net->src_ip) == 0) {
            self->x_tx_seq = ntohl(self->thdr.th_seq) + self->plen;
            self->x_tx_ack = ntohl(self->thdr.th_ack);
            self->x_src_port = ntohs(self->thdr.th_sport);
            self->x_dst_port = ntohs(self->thdr.th_dport);
        }
        else if(strcmp(net->x_src_ip, net->src_ip) == 0)    
        {
            self->thdr.th_seq = ntohl(htonl(pre_ack)- self->plen);

        }
        if (strcmp(net->x_src_ip, net->dst_ip) == 0) {
            self->x_tx_seq = ntohl(self->thdr.th_ack);
            self->x_tx_ack = ntohl(self->thdr.th_seq) + self->plen;
            self->x_src_port = ntohs(self->thdr.th_dport);
            self->x_dst_port = ntohs(self->thdr.th_sport);
        }
    }
    //0x8010 -> means there is an error

    return segm+20;
        
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen,bool mode)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)
    
    memcpy(self->pl,data,dlen);
    self->thdr.th_sport = htons(self->x_src_port);
    self->thdr.th_dport = htons(self->x_dst_port);
    self->thdr.th_seq = htonl(self->x_tx_seq);
    self->thdr.th_ack = htonl(self->x_tx_ack);
    //self->thdr.th_ack = htonl(ntohl(ntohl(self->thdr.th_seq)));
    self->plen = dlen;
    self->thdr.psh = 1;
    self->thdr.check = 0;
    if(dlen == 0) self->thdr.ack = 1;
    self->thdr.check = htons(cal_tcp_cksm(iphdr,self->thdr,data,dlen));
    sf = false;
    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

