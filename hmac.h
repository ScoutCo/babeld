/*
Copyright (c) 2018 by Clara Dô and Weronika Kolodziejak

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

/* Ed25519 sizes, matching libsodium's crypto_sign_ed25519. */
#define ED25519_PUBKEY_LEN 32
#define ED25519_SECKEY_LEN 64
#define ED25519_SIG_LEN 64
/* A "certificate" is the fleet CA's Ed25519 signature over a node's public
   key. Not X.509 — a minimal binding that avoids ASN.1 in the daemon. */
#define ED25519_CERT_LEN 64

/* Ed25519 MAC trailer layouts, distinguished by length. babeld's trailer TLV
   carries a one-byte length, so every value must fit in 255 bytes.
   - V1, phase 1 (preconfigured trusted keys): keyid || sig        = 72
   - V2, phase 2a (CA trust): keyid || pubkey || cert || sig       = 168
   Phase 2b (ephemeral) reuses the V1 MAC layout — keyid is the ephemeral key's
   fingerprint and sig is by the ephemeral key — and carries the trust chain in
   a companion SIG_CERT trailer TLV (below), because the full chain would blow
   the 255-byte trailer limit. */
#define ED25519_TRAILER_V1_LEN (KEYID_LEN + ED25519_SIG_LEN)
#define ED25519_TRAILER_V2_LEN \
    (KEYID_LEN + ED25519_PUBKEY_LEN + ED25519_CERT_LEN + ED25519_SIG_LEN)

/* SIG_CERT trailer value (phase 2b): the two-link trust chain a receiver
   needs to trust an ephemeral key, minus the per-packet signature.
     long_term_pubkey || cert || eph_pubkey || eph_auth        = 192
   cert = CA signature over long_term_pubkey; eph_auth = long-term signature
   over eph_pubkey. Self-authenticating, so it need not be covered by the MAC. */
#define ED25519_SIGCERT_LEN \
    (ED25519_PUBKEY_LEN + ED25519_CERT_LEN + ED25519_PUBKEY_LEN + ED25519_SIG_LEN)

/* SIG_NET trailer value (cert-less mode): a session binding with no CA/cert.
     long_term_pubkey || eph_pubkey || eph_auth               = 128
   Membership is open; this provides packet integrity plus network-name scoping.
   eph_auth is the long-term key's signature over eph_pubkey followed by the
   configured network name, so a session only verifies for a peer that shares
   the same network name (the name itself never travels on the wire). */
#define ED25519_SIGNET_LEN \
    (ED25519_PUBKEY_LEN + ED25519_PUBKEY_LEN + ED25519_SIG_LEN)

/* Longest network name bound into an ephemeral authorization. */
#define MAX_NETWORK_NAME 64

/* Widest trailer value across all auth types (HMAC-SHA256 is 32). */
#define MAX_DIGEST_LEN ED25519_SIGCERT_LEN

/* Configured Ed25519 trust state (see hmac.c). */
void set_ca_pubkey(const unsigned char *pubkey);
void set_own_cert(const unsigned char *cert);
void set_ed25519_ephemeral(void);
/* Opt in to on-demand certificate pull (X.509 mode): serve the cert only when
   a peer sends a CERT_REQUEST, rather than pushing it periodically in Hellos. */
void set_ed25519_cert_pull(void);
/* Set the network name bound into ephemeral authorizations. In cert-less mode
   it scopes peering (only same-named nodes verify); it is also folded into the
   authorization in the CA/X.509 modes when set. Empty name = no scoping. */
void set_ed25519_network_name(const char *name);
int add_revoked_keyid(const unsigned char *keyid);

/* X.509 identity mode (phase 3): the CA and own certificate, in DER. When
   both are set the node distributes its cert in Hellos and authenticates
   peers by cached, CA-validated certificate rather than an inline key. */
int enable_x509_ca(const unsigned char *der, int len);
int enable_x509_own(const unsigned char *der, int len);

struct key *find_key(const char *id);
struct key *find_key_by_keyid(const unsigned char *keyid);
int compute_keyid(const unsigned char *pubkey, unsigned char *keyid_return);
struct key *retain_key(struct key *key);
void release_key(struct key *key);
struct key *add_key(char *id, int type, int len, unsigned char *value);
int add_hmac(struct buffered *buf, struct interface *ifp,
             unsigned char *packet_header);
int check_hmac(const unsigned char *packet, int packetlen, int bodylen,
               const unsigned char *src, const unsigned char *dst,
               struct interface *ifp);
