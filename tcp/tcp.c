#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/jiffies.h>

#include "tcp.h"
 
static spinlock_t tcp_lock;

static unsigned int max_tcp_buffer = 0; // tcp session's buffer max length
static unsigned int max_tcp_sessions = 0; // max tcp sessions count

static unsigned int tcp_session_timeout = 0;

static struct tcp_session *tcp_sessions = NULL;

// init spin lock
static void init_tcp_lock(void) {
    spin_lock_init(&tcp_lock);
}

// init tcp sessions size of max tcp sessions
static int init_tcp_sessions(unsigned int max_sessions) {
    spin_lock(&tcp_lock);
    max_tcp_sessions = max_sessions;
    tcp_sessions = kcalloc(max_sessions, sizeof(struct tcp_session), GFP_ATOMIC);
    if (!tcp_sessions) {
        spin_unlock(&tcp_lock);
        return TCP_ALLOC_ERROR;
    }
    spin_unlock(&tcp_lock);

    return 0;
}

// init spin lock and tcp sessions array
int init_tcp(unsigned int max_sessions, unsigned int max_buffer, unsigned int timeout) {
    init_tcp_lock();
    tcp_session_timeout = timeout;
    max_tcp_buffer = max_buffer;
    
    return init_tcp_sessions(max_sessions);
}

// cleanup tcp session
static void cleanup_session(struct tcp_session *sess) {
    kfree(sess->bitmap);
    kfree(sess->buffer);
    memset(sess, 0, sizeof(struct tcp_session));
}

// deinit tcp sessions array
void deinit_tcp(void) {
    spin_lock(&tcp_lock);

    // check the tcp sessions array's length
    if (max_tcp_sessions < 1) {
        spin_unlock(&tcp_lock);
        return;
    }

    for (int i = 0; i < max_tcp_sessions; i++) {
        struct tcp_session *sess = &tcp_sessions[i];
        cleanup_session(sess);
    }
    kfree(tcp_sessions);

    tcp_sessions = NULL;
    max_tcp_buffer = 0;
    max_tcp_sessions = 0;
    tcp_session_timeout = 0;

    spin_unlock(&tcp_lock);
}

// find free index number on tcp sessions array
static int find_free_index(__be16 sport, __be32 daddr) {
    // minimum start index number
    unsigned int min = (ntohs(sport)+ntohl(daddr))%max_tcp_sessions;
    
    // find free index min to max_tcp_sessions
    for (int i = min; i < max_tcp_sessions; i++) {
        struct tcp_session *sess = &tcp_sessions[i];

        // check the lastseen and clear timeout sessions
        if (time_after(jiffies, sess->last_seen+msecs_to_jiffies(tcp_session_timeout*1000))) {
            cleanup_session(sess);
        }

        if (sess->state == SESSION_EMPTY) {
            return i;
        }
    }

    // find free index 0 to min
    for (int i = 0; i < min; i++) {
        struct tcp_session *sess = &tcp_sessions[i];

        // check the lastseen and clear timeout sessions
        if (time_after(jiffies, sess->last_seen+msecs_to_jiffies(tcp_session_timeout*1000))) {
            cleanup_session(sess);
        }

        if (sess->state == SESSION_EMPTY) {
            return i;
        }
    }

    // find free index number failed
    return TCP_SESSIONS_FULL;
}

// fetch tcp session from the tcp sessions array (caller must hold spin lock)
static struct tcp_session *fetch_tcp_session_unlock(struct iphdr *iph, struct tcphdr *tcph) {
    // minimum start index number
    unsigned int min = (ntohs(tcph->source)+ntohl(iph->daddr))%max_tcp_sessions;
    for (int i = min; i < max_tcp_sessions; i++) {
        struct tcp_session *sess = &tcp_sessions[i];   
        if (sess->state == SESSION_USED) {
            if (sess->saddr == iph->saddr && sess->daddr == iph->daddr) {
                if (sess->sport == tcph->source && sess->dport == tcph->dest) {
                    return sess;
                }
            }
        }
    }

    for (int i = 0; i < min; i++) {
        struct tcp_session *sess = &tcp_sessions[i];
        if (sess->state == SESSION_USED) {
            if (sess->saddr == iph->saddr && sess->daddr == iph->daddr) {
                if (sess->sport == tcph->source && sess->dport == tcph->dest) {
                    return sess;
                }
            }
        }
    }

    return NULL;
}

// fetch buffer from the tcp session  
char *fetch_tcp_buffer(struct iphdr *iph, struct tcphdr *tcph, unsigned int *len) {
    spin_lock(&tcp_lock);
    
    // fetch tcp session
    struct tcp_session *sess = fetch_tcp_session_unlock(iph, tcph);
    if (!sess) {
        spin_unlock(&tcp_lock);
        return NULL;
    }

    *len = sess->max_index+1;
    char *buffer = kmalloc(*len, GFP_ATOMIC);
    if (!buffer) {
        spin_unlock(&tcp_lock);
        return NULL;
    }
    memcpy(buffer, sess->buffer, *len);
    
    spin_unlock(&tcp_lock);
    return buffer;
}

// append tcp data to the tcp buffer
static int append_tcp_data(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);

    // fetch tcp session
    struct tcp_session *sess = fetch_tcp_session_unlock(iph, tcph);
    if (!sess) {
        spin_unlock(&tcp_lock);
        return TCP_SESSION_NOT_FOUND;
    }

    // calculate data's length and check the valid
    int data_len = ntohs(iph->tot_len)-((iph->ihl*4)+(tcph->doff*4));
    if (data_len <= 0) {
        spin_unlock(&tcp_lock);
        return TCP_INVALID_LENGTH;
    } 

    // calculate buffer offset
    int offset = ntohl(tcph->seq)-ntohl(sess->init_seq)-1;
    if (offset < 0) offset = 0;

    // check the buffer max length and data length
    if (offset+data_len > max_tcp_buffer) {
        if (data_len > max_tcp_buffer) {
            spin_unlock(&tcp_lock);
            return TCP_DATA_TOO_BIG;
        }

        memset(sess->buffer, 0, max_tcp_buffer);
        memset(sess->bitmap, 0, max_tcp_buffer/8+1);
        sess->max_index = 0;
        sess->init_seq = tcph->seq;
        
        offset = 0;
    }

    char *tmp = kmalloc(data_len, GFP_ATOMIC);
    if (!tmp) {
        spin_unlock(&tcp_lock);
        return TCP_ALLOC_ERROR;
    }

    int data_offset = ((char *)tcph+tcph->doff*4)-(char *)skb->data;
    if (skb_copy_bits(skb, data_offset, tmp, data_len) < 0) {
        kfree(tmp);
        spin_unlock(&tcp_lock);
        return TCP_BUFFER_COPY_ERROR;
    } 

    // linux is last wins and windows is first wins
    if (sess->os == LINUX) {
        memcpy(sess->buffer+offset, tmp, data_len);
        for (int i = 0; i < data_len; i++) {
            int pos = offset+i;
            sess->bitmap[(pos)/8] |= (1 << ((pos)%8));
        }
    } else {
        for (int i = 0; i < data_len; i++) {
            int pos = offset+i;
            if ((sess->bitmap[pos/8] >> (pos%8)) & 1) {
                continue;
            }
            sess->buffer[pos] = tmp[i];
            sess->bitmap[(pos)/8] |= (1 << ((pos)%8));
        }
    }

    int end = offset+data_len-1;
    if (end > sess->max_index) {
        sess->max_index = end;
    }
    
    sess->last_seen = jiffies;
    kfree(tmp);

    spin_unlock(&tcp_lock);
    return 0;
}

// infer the os using ttl, windows
static enum os infer_os(struct iphdr *iph, struct tcphdr *tcph) {
    int linux_score = 0, windows_score = 0;
    if (iph->ttl <= 64) {
        linux_score++;
    } else {
        windows_score++;
    }

    if (ntohs(tcph->window) == 5840) {
        linux_score++;
    } else if (ntohs(tcph->window) == 65535 || ntohs(tcph->window) == 64240) {
        windows_score++;
    }


    // if same score, return default os(linux)
    return (linux_score >= windows_score) ? LINUX:WINDOWS;
}

// add a new session to the tcp sessions array
static int new_tcp_session(struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);

    int i = find_free_index(tcph->source, iph->daddr);
    if (i < 0) {
        spin_unlock(&tcp_lock);
        return i;
    }

    char *buffer = kmalloc(max_tcp_buffer, GFP_ATOMIC);
    if (!buffer) {
        spin_unlock(&tcp_lock);
        return TCP_ALLOC_ERROR;
    }

    char *bitmap = kcalloc(max_tcp_buffer/8+1, sizeof(char), GFP_ATOMIC);
    if (!bitmap) {
        kfree(buffer);
        spin_unlock(&tcp_lock);
        return TCP_ALLOC_ERROR;
    }

    tcp_sessions[i] = (struct tcp_session){
        .saddr = iph->saddr,
        .daddr = iph->daddr,
        .sport = tcph->source,
        .dport = tcph->dest,
        .init_seq = tcph->seq,
        .buffer = buffer,
        .max_index = 0,
        .bitmap = bitmap,
        .last_seen = jiffies,
        .os = infer_os(iph, tcph),
        .state = SESSION_USED,
    };
    

    spin_unlock(&tcp_lock);
    return 0;
}

// remove tcp session to the tcp sessions array
static int remove_tcp_session(struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);

    // fetch tcp session
    struct tcp_session *sess = fetch_tcp_session_unlock(iph, tcph);
    if (!sess) {
        spin_unlock(&tcp_lock);
        return TCP_SESSION_NOT_FOUND;
    }

    cleanup_session(sess);

    spin_unlock(&tcp_lock);
    return 0;
}

// parse tcp packet
void parse_tcp(struct iphdr *iph, struct sk_buff *skb) {
    const struct tcphdr *tcph = tcp_hdr(skb);
    if (tcph->syn && !tcph->ack) {
        switch (new_tcp_session(iph, tcph)) {
            case TCP_ALLOC_ERROR:
                printk(KERN_ERR "tcp new connection error: alloc\n");
                return;
            case TCP_SESSIONS_FULL:
                printk(KERN_ERR "tcp new connection error: sessions array is full\n");
                return;
        }
    } else if (tcph->fin || tcph->rst) {
        remove_tcp_session(iph, tcph);
    } else {
        switch (append_tcp_data(skb, iph, tcph)) {
            case TCP_INVALID_LENGTH:
                printk(KERN_ERR "tcp add data error: invalid length\n");
                return;
            case TCP_BUFFER_COPY_ERROR:
                printk(KERN_ERR "tcp add data error: buffer copy\n");
                return;
        }
    }
}
