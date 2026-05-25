## LKM TCP Reassembly
It works on the Linux kernel and is code that tracks and reassembles a unidirectional TCP connection.

## Features
1. Creates a new session based on a TCP SYN packet.
2. Calculates a simple minimum index based on the source port and destination address, and places the session into a fixed buffer.
3. Repositions data into the correct location in the buffer using the TCP Sequence Number.
4. Estimates the source OS based on TTL and TCP Window Size.
5. Applies an overlap policy based on the estimated source OS.
6. Handles sessions with no activity for a certain period of time as timed out.

## Public API
```c
// Initializes the TCP reassembly module.
int init_tcp(unsigned int max_sessions, unsigned int max_buffer, unsigned int timeout)
```
Arguments:
* `max_sessions`: Maximum number of TCP sessions
* `max_buffer`: Maximum buffer size per session (bytes)
* `timeout`: Session timeout period (seconds)

Return values:
* Success: `0`
* Memory allocation failure: `TCP_ALLOC_ERROR`

---

```c
// Parses a received TCP packet and updates the session state.
void parse_tcp(struct iphdr *iph, struct sk_buff *skb)
```
Arguments:
* `iph`: IP header
* `skb`: Socket buffer

---

```c
// Returns the reassembled TCP data.
char *fetch_tcp_buffer(struct iphdr *iph, struct tcphdr *tcph, unsigned int *len)
```
Arguments:
* `iph`: IP header
* `tcph`: TCP header
* `len`: Variable for storing the length of the returned data

Return values:
* Success: Pointer to a newly allocated buffer
* Failure: `NULL`

The returned buffer must be freed by the caller using `kfree()`.

---

```c
// Releases all sessions and internal buffers.
void deinit_tcp(void)
```
