#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;
/*
{
                   uint8_t sadb_msg_version;
                   uint8_t sadb_msg_type;
                   uint8_t sadb_msg_errno;
                   uint8_t sadb_msg_satype;
                   uint16_t sadb_msg_len;
                   uint16_t sadb_msg_reserved;
                   uint32_t sadb_msg_seq;
                   uint32_t sadb_msg_pid;
};
*/
/*
struct sadb_ext {
                   uint16_t sadb_ext_len;
                   uint16_t sadb_ext_type;
           };
           /* sizeof(struct sadb_ext) == 4 
*/
/*
struct sadb_sa {
                   uint16_t sadb_sa_len;
                   uint16_t sadb_sa_exttype;
                   uint32_t sadb_sa_spi;
                   uint8_t sadb_sa_replay;
                   uint8_t sadb_sa_state;
                   uint8_t sadb_sa_auth;
                   uint8_t sadb_sa_encrypt;
                   uint32_t sadb_sa_flags;
           };
*/
/*
struct sadb_address {
                   uint16_t sadb_address_len;
                   uint16_t sadb_address_exttype;
                   uint8_t sadb_address_proto;
                   uint8_t sadb_address_prefixlen;
                   uint16_t sadb_address_reserved;
           };
*/
/*
struct sadb_key {
                   uint16_t sadb_key_len;
                   uint16_t sadb_key_exttype;
                   uint16_t sadb_key_bits;
                   uint16_t sadb_key_reserved;
           };
*/
//get the structure is 
bool sign = true;
void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
    unsigned char    buf[4096];
    struct sadb_msg msg;
    struct sadb_ext* get_the_key;
    struct sadb_key* real_key;
    int s = socket(PF_KEY,SOCK_RAW,PF_KEY_V2);
    bzero(&msg, sizeof (msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof (msg) / 8;
    msg.sadb_msg_pid = getpid();
    int flag = write(s,&msg,sizeof (msg));
    struct sadb_msg* msgp;
    int len = read(s, &buf, sizeof(buf));
    // Base + SA + address + key
    int n = 184;
    
    /*get_the_key = (struct sadb_ext*) (buf+n); // get the SA
    n = n+get_the_key -> sadb_ext_len*8;
    get_the_key = (struct sadb_ext*) (buf+n);//get the lifetime
    n = n + get_the_key -> sadb_ext_len*8;
    get_the_key = (struct sadb_ext*) (buf+n); //get the lifetime
    n = n + get_the_key -> sadb_ext_len*8;
    get_the_key = (struct sadb_ext*) (buf+n); //get the lifetime
    n = n + get_the_key -> sadb_ext_len*8;
    get_the_key = (struct sadb_ext*) (buf+n); //get the add src
    n = n + get_the_key -> sadb_ext_len*8;
    get_the_key = (struct sadb_ext*) (buf+n); //get the dst
    n = n + get_the_key -> sadb_ext_len*8;
    real_key = (struct sadb_key*) (buf+n); //get the key
    n = n + 8;*/
    //printf("%d\n",n);
    memcpy(key,buf+n,16);
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)
    if(sign)
    {
        self -> pad = (uint8_t*) malloc (self->tlr.pad_len * sizeof(uint8_t));
        for(int i = 1 ; i<=self->tlr.pad_len ; i++)
        {
            self -> pad[i-1] = i; 
        }
        return self->pad;
    }
    else
    {
        self->tlr.pad_len = 2;
        self -> pad = (uint8_t*) malloc (self->tlr.pad_len * sizeof(uint8_t));
        for(int i = 1 ; i<=self->tlr.pad_len ; i++)
        {
            self -> pad[i-1] = i; 
        }
        return self->pad;
    }
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb
    memcpy(buff,&self->hdr,sizeof(EspHeader));
    nb += sizeof(EspHeader);
    // convert the bytes into right endian
    EspHeader* test = (struct EspHeader*)buff;
    //test -> spi = ntohl(test -> spi);
    //test -> seq = ntohl(test -> seq);
    memcpy(buff+nb,self->pl,self->plen);
    nb += self->plen;
    memcpy(buff+nb,self->pad,self->tlr.pad_len);
    nb += self->tlr.pad_len;

    memcpy(buff+nb,&self->tlr,sizeof(EspTrailer));
    //convert the bytes into right endian
    nb += sizeof(EspTrailer);
    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP
    // as if we know the length of esp's header is 8 bytes
    int hl = 8;
    int payload_len = esp_len - hl;
    struct esp_header* h;
    h = (struct esp_header*) esp_pkt;
    struct esp_trailer* tail = (struct esp_trailer*)(esp_pkt+esp_len-12-2);
    self->plen = payload_len-tail->pad_len-sizeof(struct esp_trailer)-12;
    self->hdr.spi = (h->spi);
    self->hdr.seq = (h->seq);

    //printf("%x\n",ntohl(h->spi));
    return esp_pkt+hl;
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
    self->hdr.spi = (esp_hdr_rec.spi);
    self->hdr.seq = htonl( esp_hdr_rec.seq+1);
    self->tlr.pad_len = (14+sizeof(struct iphdr)+self->plen+sizeof(struct esp_header)+sizeof(struct tcphdr))%4;
    self->tlr.nxt = p;
    esp_hdr_rec.seq++;
    // Need to update the information from fmt
    if(self->plen == 20) sign = false;
    else sign = true;

}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}
