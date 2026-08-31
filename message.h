/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#define MAX_BUFFERED_UPDATES 200
/* Room reserved for the auth trailer TLVs. Large enough for the worst case:
   a Hello carrying the fragmented X.509 certificate (a few ~255-byte
   CERT_FRAG TLVs) plus the SIG_SESSION and MAC TLVs. Non-cert packets use
   only a small fraction. */
#define MAX_HMAC_SPACE 1024

#define MESSAGE_PAD1 0
#define MESSAGE_PADN 1
#define MESSAGE_ACK_REQ 2
#define MESSAGE_ACK 3
#define MESSAGE_HELLO 4
#define MESSAGE_IHU 5
#define MESSAGE_ROUTER_ID 6
#define MESSAGE_NH 7
#define MESSAGE_UPDATE 8
#define MESSAGE_REQUEST 9
#define MESSAGE_MH_REQUEST 10

#define MESSAGE_MAC 16
#define MESSAGE_PC 17
#define MESSAGE_CHALLENGE_REQUEST 18
#define MESSAGE_CHALLENGE_REPLY 19
/* Babel-SIG (experimental), all carried in the trailer like MAC/PC:
   SIG_CERT   - minimal-cert ephemeral trust chain (phase 2b)
   CERT_FRAG  - a fragment of this node's X.509 certificate (phase 3), sent in
                Hellos periodically; a receiver concatenates the fragments in
                one packet to reconstruct the DER
   SIG_SESSION- X.509-mode session binding: long-term identity fingerprint +
                ephemeral key + its authorization; references a cached cert
   CERT_REQUEST- on-demand cert pull: value is an identity fingerprint; the
                node holding that identity serves its cert (as CERT_FRAGs) on
                its next Hello. Processed before the MAC, since the pull has to
                bootstrap before either side can verify the other's session. */
#define MESSAGE_SIG_CERT 20
#define MESSAGE_CERT_FRAG 21
#define MESSAGE_SIG_SESSION 22
#define MESSAGE_CERT_REQUEST 23
/* SIG_NET - cert-less session binding: long-term pubkey + ephemeral key + its
   authorization, with no certificate. Provides packet integrity and, via the
   network name folded into the authorization, network-name scoping. */
#define MESSAGE_SIG_NET 24

/* Protocol extension through sub-TLVs. */
#define SUBTLV_PAD1 0
#define SUBTLV_PADN 1
#define SUBTLV_DIVERSITY 2       /* Also known as babelz. */
#define SUBTLV_TIMESTAMP 3       /* Used to compute RTT. */
#define SUBTLV_SOURCE_PREFIX 128 /* Source-specific routing. */

/* Address encodings */
#define AE_WILDCARD 0
#define AE_IPV4 1
#define AE_IPV6 2
#define AE_IPV6_LOCAL 3
#define AE_V4VIAV6 4

extern unsigned short myseqno;
extern struct timeval seqno_time;

extern int broadcast_ihu;
extern int split_horizon;

extern unsigned char packet_header[4];

void parse_packet(const unsigned char *from, struct interface *ifp,
                  const unsigned char *packet, int packetlen,
                  const unsigned char *to);
void flushbuf(struct buffered *buf, struct interface *ifp);
void flushupdates(struct interface *ifp);
int send_pc(struct buffered *buf, struct interface *ifp);
void send_ack(struct neighbour *neigh, unsigned short nonce,
              unsigned short interval);
int send_challenge_request(struct neighbour *neigh);
int send_challenge_reply(struct neighbour *neigh,
                         const unsigned char *crypto_nonce, int len);
void send_multicast_hello(struct interface *ifp, unsigned interval, int force);
void send_unicast_hello(struct neighbour *neigh, unsigned interval, int force);
void send_hello(struct interface *ifp);
void flush_unicast(int dofree);
void send_update(struct interface *ifp, int urgent,
                 const unsigned char *prefix, unsigned char plen,
                 const unsigned char *src_prefix, unsigned char src_plen);
void send_update_resend(struct interface *ifp,
                        const unsigned char *prefix, unsigned char plen,
                        const unsigned char *src_prefix,
                        unsigned char src_plen);
void send_wildcard_retraction(struct interface *ifp);
void send_self_update(struct interface *ifp);
void send_ihu(struct neighbour *neigh, struct interface *ifp);
void send_marginal_ihu(struct interface *ifp);
void send_multicast_request(struct interface *ifp,
                  const unsigned char *prefix, unsigned char plen,
                  const unsigned char *src_prefix, unsigned char src_plen);
void send_unicast_request(struct neighbour *neigh,
                          const unsigned char *prefix, unsigned char plen,
                          const unsigned char *src_prefix,
                          unsigned char src_plen);
void
send_multicast_multihop_request(struct interface *ifp,
                                const unsigned char *prefix, unsigned char plen,
                                const unsigned char *src_prefix,
                                unsigned char src_plen,
                                unsigned short seqno, const unsigned char *id,
                                unsigned short hop_count);
void
send_unicast_multihop_request(struct neighbour *neigh,
                              const unsigned char *prefix, unsigned char plen,
                              const unsigned char *src_prefix,
                              unsigned char src_plen,
                              unsigned short seqno, const unsigned char *id,
                              unsigned short hop_count);
void send_request_resend(const unsigned char *prefix, unsigned char plen,
                         const unsigned char *src_prefix,
                         unsigned char src_plen,
                         unsigned short seqno, unsigned char *id);
void handle_request(struct neighbour *neigh, const unsigned char *prefix,
                    unsigned char plen,
                    const unsigned char *src_prefix, unsigned char src_plen,
                    unsigned char hop_count,
                    unsigned short seqno, const unsigned char *id);
