#ifndef TCP_H
#define TCP_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/jiffies.h>

enum {
    TCP_ALLOC_ERROR = -1,
    TCP_SESSION_NOT_FOUND = -2,
    TCP_INVALID_LENGTH = -3,
    TCP_BUFFER_COPY_ERROR = -4,
    TCP_SESSIONS_FULL = -5,
    TCP_DATA_TOO_BIG = -6,
};

enum session_state {
    SESSION_EMPTY = 0,
    SESSION_USED = 1,
};

enum os {
    LINUX,
    WINDOWS,
};

struct tcp_session {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;

    __be32 init_seq;

    char *buffer;
    unsigned int max_index;

    char *bitmap;
    
    unsigned long last_seen;

    enum os os;
    enum session_state state;
};

int init_tcp(unsigned int max_sessions, unsigned int max_buffer, unsigned int timeout);
void deinit_tcp(void);

void parse_tcp(struct iphdr *iph, struct sk_buff *skb);
char *fetch_tcp_buffer(struct iphdr *iph, struct tcphdr *tcph, unsigned int *len);

#endif
