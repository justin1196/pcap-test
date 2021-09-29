# include <stdio.h>
# include <stdlib.h>
# include <pcap.h>

typedef struct {
    u_int8_t  ether_shost[6];/* destination ethernet address */
    u_int8_t  ether_dhost[6];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */

    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int8_t ip_src[4]; /* source address */
    u_int8_t ip_drc[4]; /* dest address */

    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int8_t th_seq[4];          /* sequence number */
    u_int8_t th_ack[4];          /* acknowledgement number */
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
    u_int8_t data[];
}my_packet; 
