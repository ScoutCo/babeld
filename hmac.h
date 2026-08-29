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

/* Two Ed25519 trailer layouts, distinguished by length:
   - phase 1 (preconfigured trusted keys): keyid || sig            = 72
   - phase 2 (CA trust): keyid || pubkey || cert || sig            = 168
   In phase 2 the signer's public key travels in the packet; the receiver
   trusts it because `cert` verifies against the configured CA, so no per-peer
   configuration is needed. */
#define ED25519_TRAILER_V1_LEN (KEYID_LEN + ED25519_SIG_LEN)
#define ED25519_TRAILER_V2_LEN \
    (KEYID_LEN + ED25519_PUBKEY_LEN + ED25519_CERT_LEN + ED25519_SIG_LEN)

/* Widest trailer value across all auth types (HMAC-SHA256 is 32). */
#define MAX_DIGEST_LEN ED25519_TRAILER_V2_LEN

/* Configured Ed25519 trust state (see hmac.c). */
void set_ca_pubkey(const unsigned char *pubkey);
void set_own_cert(const unsigned char *cert);
int add_revoked_keyid(const unsigned char *keyid);

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
