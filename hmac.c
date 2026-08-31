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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <sodium.h>

#include "rfc6234/sha.h"
#include "BLAKE2/ref/blake2.h"

#include "babeld.h"
#include "interface.h"
#include "neighbour.h"
#include "util.h"
#include "hmac.h"
#include "x509.h"
#include "configuration.h"
#include "message.h"

struct key **keys = NULL;
int numkeys = 0, maxkeys = 0;

/* CA-trust state (Babel-SIG phase 2a). A node needs only the fleet CA public
   key plus its own CA-signed certificate; peers are trusted because the CA
   vouches for the public key they carry in each packet, not because they are
   preconfigured. */
static unsigned char ca_pubkey[ED25519_PUBKEY_LEN];
static int ca_set = 0;
static unsigned char own_cert[ED25519_CERT_LEN];
static int own_cert_set = 0;
/* Revoked key ids (a minimal CRL). */
static unsigned char (*revoked_keyids)[KEYID_LEN] = NULL;
static int num_revoked = 0;

/* Ephemeral session key (Babel-SIG phase 2b). When enabled, the node mints an
   ephemeral keypair at first use and the long-term key authorizes it once
   (eph_auth); packets are then signed by the ephemeral key so the long-term
   identity key never appears in the per-packet hot path. A restart mints a
   fresh ephemeral, giving a new session for free. */
static int ephemeral_enabled = 0;
static int have_ephemeral = 0;
static unsigned char ephemeral_sk[ED25519_SECKEY_LEN];
static unsigned char ephemeral_auth[ED25519_SIG_LEN];
static unsigned char ephemeral_keyid[KEYID_LEN];

void
set_ed25519_ephemeral(void)
{
    ephemeral_enabled = 1;
}

/* Session cache: validated ephemeral keys, so that steady-state packets can
   carry only the small MAC (ephemeral keyid || sig) while the trust chain
   travels in Hellos. Keyed by the ephemeral keyid; the long-term keyid is
   kept so a revocation that lands after caching is still honored. */
static int keyid_revoked(const unsigned char *keyid);

#define MAX_SESSIONS 512
struct session {
    unsigned char eph_keyid[KEYID_LEN];
    unsigned char eph_pubkey[ED25519_PUBKEY_LEN];
    unsigned char lt_keyid[KEYID_LEN];
    int used;
};
static struct session sessions[MAX_SESSIONS];
static int session_rr = 0;

static void
session_upsert(const unsigned char *eph_keyid, const unsigned char *eph_pubkey,
               const unsigned char *lt_keyid)
{
    int i, slot = -1;
    for(i = 0; i < MAX_SESSIONS; i++) {
        if(sessions[i].used &&
           memcmp(sessions[i].eph_keyid, eph_keyid, KEYID_LEN) == 0) {
            slot = i;
            break;
        }
        if(slot < 0 && !sessions[i].used)
            slot = i;
    }
    if(slot < 0)
        slot = session_rr++ % MAX_SESSIONS; /* table full: evict round-robin */
    memcpy(sessions[slot].eph_keyid, eph_keyid, KEYID_LEN);
    memcpy(sessions[slot].eph_pubkey, eph_pubkey, ED25519_PUBKEY_LEN);
    memcpy(sessions[slot].lt_keyid, lt_keyid, KEYID_LEN);
    sessions[slot].used = 1;
}

/* Return a cached ephemeral public key for eph_keyid, or NULL if unknown or
   its identity has since been revoked. */
static const unsigned char *
session_lookup(const unsigned char *eph_keyid)
{
    int i;
    for(i = 0; i < MAX_SESSIONS; i++) {
        if(sessions[i].used &&
           memcmp(sessions[i].eph_keyid, eph_keyid, KEYID_LEN) == 0) {
            if(keyid_revoked(sessions[i].lt_keyid))
                return NULL;
            return sessions[i].eph_pubkey;
        }
    }
    return NULL;
}

/* X.509 identity mode (phase 3). When a CA and an own certificate are both
   configured, the node advertises its cert in Hellos (fragmented) and
   authenticates peers by their cached, CA-validated certificate. */
static int x509_ca_set = 0, x509_own_set = 0;

int
enable_x509_ca(const unsigned char *der, int len)
{
    if(!x509_set_ca(der, len))
        return 0;
    x509_ca_set = 1;
    return 1;
}

int
enable_x509_own(const unsigned char *der, int len)
{
    if(!x509_set_own(der, len))
        return 0;
    x509_own_set = 1;
    return 1;
}

static int
x509_mode(void)
{
    return x509_ca_set && x509_own_set;
}

/* X.509 mode always signs per-packet with an ephemeral key. */
static int
using_ephemeral(void)
{
    return ephemeral_enabled || x509_mode();
}

/* Peer identity cache: long-term identity fingerprint -> CA-validated raw
   Ed25519 public key, populated when a peer's certificate is reassembled and
   validated. Bounded, round-robin eviction. */
#define MAX_IDENTITIES 512
struct identity {
    unsigned char fp[KEYID_LEN];
    unsigned char pubkey[ED25519_PUBKEY_LEN];
    int used;
};
static struct identity identities[MAX_IDENTITIES];
static int identity_rr = 0;

static void
identity_upsert(const unsigned char *fp, const unsigned char *pubkey)
{
    int i, slot = -1;
    for(i = 0; i < MAX_IDENTITIES; i++) {
        if(identities[i].used && memcmp(identities[i].fp, fp, KEYID_LEN) == 0) {
            slot = i;
            break;
        }
        if(slot < 0 && !identities[i].used)
            slot = i;
    }
    if(slot < 0)
        slot = identity_rr++ % MAX_IDENTITIES;
    memcpy(identities[slot].fp, fp, KEYID_LEN);
    memcpy(identities[slot].pubkey, pubkey, ED25519_PUBKEY_LEN);
    identities[slot].used = 1;
}

static const unsigned char *
identity_lookup(const unsigned char *fp)
{
    int i;
    if(keyid_revoked(fp))
        return NULL;
    for(i = 0; i < MAX_IDENTITIES; i++) {
        if(identities[i].used && memcmp(identities[i].fp, fp, KEYID_LEN) == 0)
            return identities[i].pubkey;
    }
    return NULL;
}

/* On-demand certificate pull (opt-in, X.509 mode). Instead of pushing the
   certificate in every Nth Hello, a node advertises only its small session
   binding and serves its certificate when a peer explicitly asks for it. */
static int cert_pull_enabled = 0;

void
set_ed25519_cert_pull(void)
{
    cert_pull_enabled = 1;
}

/* This node's own identity fingerprint, so we can recognise a CERT_REQUEST
   that targets us. Derived lazily from the configured own certificate. */
static unsigned char own_fp[KEYID_LEN];
static int own_fp_set = 0;

static const unsigned char *
own_identity_fp(void)
{
    unsigned char pub[ED25519_PUBKEY_LEN];
    if(own_fp_set)
        return own_fp;
    if(x509_own_pubkey(pub) != 1)
        return NULL;
    if(compute_keyid(pub, own_fp) != 0)
        return NULL;
    own_fp_set = 1;
    return own_fp;
}

/* Identities referenced by a peer (in a SIG_SESSION) whose certificate we do
   not yet hold: we ask for these in our own Hellos, rate-limited per identity.
   Serving our own certificate is likewise rate-limited. */
#define MAX_WANTED 64
#define CERT_REQUEST_INTERVAL 5   /* seconds between requests for one identity */
#define CERT_SERVE_INTERVAL 5     /* seconds between servings of our own cert */
struct wanted {
    unsigned char fp[KEYID_LEN];
    time_t last_req;
    int used;
};
static struct wanted wanted[MAX_WANTED];
static time_t cert_serve_due = 0;  /* a peer asked; serve on the next Hello */
static time_t cert_served_at = 0;

static void
want_identity(const unsigned char *fp)
{
    int i, slot = -1;
    for(i = 0; i < MAX_WANTED; i++) {
        if(wanted[i].used && memcmp(wanted[i].fp, fp, KEYID_LEN) == 0)
            return;                    /* already queued */
        if(slot < 0 && !wanted[i].used)
            slot = i;
    }
    if(slot < 0)
        slot = 0;                      /* table full: reuse the first slot */
    memcpy(wanted[slot].fp, fp, KEYID_LEN);
    wanted[slot].last_req = 0;
    wanted[slot].used = 1;
}

static void
unwant_identity(const unsigned char *fp)
{
    int i;
    for(i = 0; i < MAX_WANTED; i++)
        if(wanted[i].used && memcmp(wanted[i].fp, fp, KEYID_LEN) == 0)
            wanted[i].used = 0;
}

/* Emit a CERT_REQUEST trailer TLV (value = wanted identity fingerprint) for
   each identity whose certificate we still lack, respecting the per-identity
   rate limit. Starts writing at buf->buf[i]; returns the new offset. */
static int
emit_cert_requests(struct buffered *buf, int i)
{
    int w;
    for(w = 0; w < MAX_WANTED; w++) {
        if(!wanted[w].used)
            continue;
        if(wanted[w].last_req != 0 &&
           now.tv_sec - wanted[w].last_req < CERT_REQUEST_INTERVAL)
            continue;
        if(i + 2 + KEYID_LEN + 2 + MAX_DIGEST_LEN > buf->size)
            break;
        buf->buf[i++] = MESSAGE_CERT_REQUEST;
        buf->buf[i++] = KEYID_LEN;
        memcpy(buf->buf + i, wanted[w].fp, KEYID_LEN);
        i += KEYID_LEN;
        wanted[w].last_req = now.tv_sec;
    }
    return i;
}

/* Mint the ephemeral keypair and have the long-term key authorize it. */
static int
ensure_ephemeral(const struct key *longterm)
{
    unsigned char ephemeral_pk[ED25519_PUBKEY_LEN];
    if(have_ephemeral)
        return 0;
    if(longterm->len != ED25519_SECKEY_LEN)
        return -1;
    if(crypto_sign_ed25519_keypair(ephemeral_pk, ephemeral_sk) != 0)
        return -1;
    if(crypto_sign_ed25519_detached(ephemeral_auth, NULL,
                                    ephemeral_pk, ED25519_PUBKEY_LEN,
                                    longterm->value) != 0)
        return -1;
    if(compute_keyid(ephemeral_pk, ephemeral_keyid) != 0)
        return -1;
    have_ephemeral = 1;
    return 0;
}

void
set_ca_pubkey(const unsigned char *pubkey)
{
    memcpy(ca_pubkey, pubkey, ED25519_PUBKEY_LEN);
    ca_set = 1;
}

void
set_own_cert(const unsigned char *cert)
{
    memcpy(own_cert, cert, ED25519_CERT_LEN);
    own_cert_set = 1;
}

int
add_revoked_keyid(const unsigned char *keyid)
{
    unsigned char (*new_revoked)[KEYID_LEN];
    new_revoked = realloc(revoked_keyids, (num_revoked + 1) * KEYID_LEN);
    if(new_revoked == NULL)
        return -1;
    revoked_keyids = new_revoked;
    memcpy(revoked_keyids[num_revoked++], keyid, KEYID_LEN);
    return 0;
}

static int
keyid_revoked(const unsigned char *keyid)
{
    int i;
    for(i = 0; i < num_revoked; i++) {
        if(memcmp(revoked_keyids[i], keyid, KEYID_LEN) == 0)
            return 1;
    }
    return 0;
}

struct key *
find_key(const char *id)
{
    int i;
    for(i = 0; i < numkeys; i++) {
        if(strcmp(keys[i]->id, id) == 0)
            return retain_key(keys[i]);
    }
    return NULL;
}

/* The public key of an Ed25519 key. A signing key stores libsodium's 64-byte
   secret key, whose second half is the public key; a verify-only key stores
   the 32-byte public key directly. */
static const unsigned char *
ed25519_pubkey(const struct key *key)
{
    if(key->len == ED25519_SECKEY_LEN)
        return key->value + 32;
    return key->value;
}

/* An 8-byte fingerprint of a public key, used as the wire key id. */
int
compute_keyid(const unsigned char *pubkey, unsigned char *keyid_return)
{
    return crypto_generichash(keyid_return, KEYID_LEN,
                              pubkey, ED25519_PUBKEY_LEN, NULL, 0);
}

struct key *
find_key_by_keyid(const unsigned char *keyid)
{
    int i;
    for(i = 0; i < numkeys; i++) {
        if(keys[i]->type == AUTH_TYPE_ED25519 &&
           memcmp(keys[i]->keyid, keyid, KEYID_LEN) == 0)
            return keys[i];
    }
    return NULL;
}

struct key *
retain_key(struct key *key)
{
    assert(key->ref_count < 0xffff);
    key->ref_count++;
    return key;
}

void
release_key(struct key *key)
{
    assert(key->ref_count > 0);
    key->ref_count--;
}

struct key *
add_key(char *id, int type, int len, unsigned char *value)
{
    struct key *key;

    assert(value != NULL && type != AUTH_TYPE_NONE);

    key = find_key(id);
    if(key) {
        key->type = type;
        key->len = len;
        key->value = value;
        if(type == AUTH_TYPE_ED25519)
            compute_keyid(len == ED25519_SECKEY_LEN ? value + 32 : value,
                          key->keyid);
        return key;
    }

    if(type == AUTH_TYPE_NONE)
        return NULL;
    if(numkeys >= maxkeys) {
        struct key **new_keys;
        int n = maxkeys < 1 ? 8 : 2 * maxkeys;
        new_keys = realloc(keys, n * sizeof(struct key*));
        if(new_keys == NULL)
            return NULL;
        maxkeys = n;
        keys = new_keys;
    }

    key = calloc(1, sizeof(struct key));
    if(key == NULL)
        return NULL;
    key->id = id;
    key->type = type;
    key->len = len;
    key->value = value;
    if(type == AUTH_TYPE_ED25519)
        compute_keyid(len == ED25519_SECKEY_LEN ? value + 32 : value,
                      key->keyid);

    keys[numkeys++] = key;
    return key;
}

static int
compute_hmac(const unsigned char *src, const unsigned char *dst,
             const unsigned char *packet_header,
             const unsigned char *body, int bodylen, struct key *key,
             unsigned char *hmac_return)
{
    unsigned char port[2];
    int rc;

    DO_HTONS(port, (unsigned short)protocol_port);
    switch(key->type) {
    case AUTH_TYPE_SHA256: {
        SHA256Context inner, outer;
        unsigned char ipad[64], ihash[32], opad[64];
        if(key->len != 64)
            return -1;
        for(int i = 0; i < 64; i++)
            ipad[i] = key->value[i] ^ 0x36;
        rc = SHA256Reset(&inner);
        if(rc < 0)
            return -1;
        rc = SHA256Input(&inner, ipad, 64);
        if(rc < 0)
            return -1;

        rc = SHA256Input(&inner, src, 16);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&inner, port, 2);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&inner, dst, 16);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&inner, port, 2);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&inner, packet_header, 4);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&inner, body, bodylen);
        if(rc != 0)
            return -1;

        rc = SHA256Result(&inner, ihash);
        if(rc != 0)
            return -1;

        for(int i = 0; i < 64; i++)
            opad[i] = key->value[i] ^ 0x5c;

        rc = SHA256Reset(&outer);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&outer, opad, 64);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&outer, ihash, 32);
        if(rc != 0)
            return -1;
        rc = SHA256Result(&outer, hmac_return);
        if(rc < 0)
            return -1;
        return 32;
    }
    case AUTH_TYPE_BLAKE2S128: {
        blake2s_state s;
        if(key->len > 32)
            return -1;
        rc = blake2s_init_key(&s, 16, key->value, key->len);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, src, 16);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, port, 2);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, dst, 16);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, port, 2);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, packet_header, 4);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, body, bodylen);
        if(rc < 0)
            return -1;
        rc = blake2s_final(&s, hmac_return, 16);
        if(rc < 0)
            return -1;

        return 16;
    }
    default:
        return -1;
    }
}

/* The bytes an Ed25519 signature covers: the same pseudo-header the HMAC
   types authenticate (source and destination address and port), then the
   4-byte packet header, then the packet body. Returns a malloc'd buffer and
   its length, or NULL on failure. */
static unsigned char *
build_signed_region(const unsigned char *src, const unsigned char *dst,
                    const unsigned char *packet_header,
                    const unsigned char *body, int bodylen, int *len_return)
{
    unsigned char port[2];
    int len = 16 + 2 + 16 + 2 + 4 + bodylen;
    unsigned char *region = malloc(len);
    int o = 0;

    if(region == NULL)
        return NULL;
    DO_HTONS(port, (unsigned short)protocol_port);
    memcpy(region + o, src, 16); o += 16;
    memcpy(region + o, port, 2); o += 2;
    memcpy(region + o, dst, 16); o += 16;
    memcpy(region + o, port, 2); o += 2;
    memcpy(region + o, packet_header, 4); o += 4;
    memcpy(region + o, body, bodylen); o += bodylen;
    *len_return = o;
    return region;
}

/* Ed25519 trailer value. With a CA certificate configured, the layout is
   keyid || pubkey || cert || sig (V2): the signer's public key and its CA
   signature travel with every packet so a receiver needs only the CA to
   trust it. Without a cert it is keyid || sig (V1), verified against a
   preconfigured trusted key. Returns the value length or -1. */
static int
sign_ed25519(const unsigned char *src, const unsigned char *dst,
             const unsigned char *packet_header,
             const unsigned char *body, int bodylen, struct key *key,
             unsigned char *value_return)
{
    unsigned char *region;
    int regionlen, rc, o = 0;

    if(key->len != ED25519_SECKEY_LEN)
        return -1;
    region = build_signed_region(src, dst, packet_header, body, bodylen,
                                 &regionlen);
    if(region == NULL)
        return -1;

    if(using_ephemeral()) {
        /* Ephemeral: the MAC value is keyid(ephemeral) || sig(ephemeral). The
           trust chain (minimal SIG_CERT, or X.509 cert + SIG_SESSION) travels
           separately in companion trailer TLVs. */
        if(ensure_ephemeral(key) != 0) {
            free(region);
            return -1;
        }
        memcpy(value_return, ephemeral_keyid, KEYID_LEN);
        o = KEYID_LEN;
        rc = crypto_sign_ed25519_detached(value_return + o, NULL,
                                          region, regionlen, ephemeral_sk);
    } else {
        memcpy(value_return, key->keyid, KEYID_LEN);
        o = KEYID_LEN;
        if(own_cert_set) {
            /* V2: long-term key travels with its CA cert. */
            memcpy(value_return + o, key->value + 32, ED25519_PUBKEY_LEN);
            o += ED25519_PUBKEY_LEN;
            memcpy(value_return + o, own_cert, ED25519_CERT_LEN);
            o += ED25519_CERT_LEN;
        }
        rc = crypto_sign_ed25519_detached(value_return + o, NULL,
                                          region, regionlen, key->value);
    }
    free(region);
    if(rc != 0)
        return -1;
    return o + ED25519_SIG_LEN;
}

/* Write the SIG_CERT trailer value: the ephemeral trust chain
   long_term_pubkey || cert || eph_pubkey || eph_auth. Requires a minted
   ephemeral key. Returns the length or -1. */
static int
build_sig_cert(struct key *key, unsigned char *value_return)
{
    int o = 0;
    if(ensure_ephemeral(key) != 0)
        return -1;
    memcpy(value_return + o, key->value + 32, ED25519_PUBKEY_LEN);
    o += ED25519_PUBKEY_LEN;
    memcpy(value_return + o, own_cert, ED25519_CERT_LEN);
    o += ED25519_CERT_LEN;
    memcpy(value_return + o, ephemeral_sk + 32, ED25519_PUBKEY_LEN);
    o += ED25519_PUBKEY_LEN;
    memcpy(value_return + o, ephemeral_auth, ED25519_SIG_LEN);
    o += ED25519_SIG_LEN;
    return o;
}

/* Write the SIG_SESSION trailer value (X.509 mode): the node's long-term
   identity fingerprint, its ephemeral public key, and the long-term key's
   authorization of that ephemeral key. The identity fingerprint references a
   certificate the receiver validated and cached from a CERT_FRAG. 104 bytes. */
static int
build_sig_session(struct key *key, unsigned char *value_return)
{
    if(ensure_ephemeral(key) != 0)
        return -1;
    memcpy(value_return, key->keyid, KEYID_LEN);
    memcpy(value_return + KEYID_LEN, ephemeral_sk + 32, ED25519_PUBKEY_LEN);
    memcpy(value_return + KEYID_LEN + ED25519_PUBKEY_LEN,
           ephemeral_auth, ED25519_SIG_LEN);
    return KEYID_LEN + ED25519_PUBKEY_LEN + ED25519_SIG_LEN;
}

/* Emit this node's X.509 certificate as consecutive CERT_FRAG trailer TLVs
   (each value <= 240 bytes) starting at buf->buf[*i], advancing *i. Returns 0,
   or -1 if it would overflow. */
#define CERT_FRAG_MAX 240
static int
emit_cert_frags(struct buffered *buf, int *i)
{
    int derlen, off;
    const unsigned char *der = x509_own_der(&derlen);
    if(der == NULL || derlen <= 0)
        return 0;
    for(off = 0; off < derlen; off += CERT_FRAG_MAX) {
        int frag = derlen - off;
        if(frag > CERT_FRAG_MAX)
            frag = CERT_FRAG_MAX;
        if(*i + 2 + frag + 2 + MAX_DIGEST_LEN > buf->size)
            return -1;
        buf->buf[(*i)++] = MESSAGE_CERT_FRAG;
        buf->buf[(*i)++] = frag;
        memcpy(buf->buf + *i, der + off, frag);
        *i += frag;
    }
    return 0;
}

/* Does the packet body contain a Hello TLV? The trust chain is attached only
   to such packets, so it travels at Hello cadence rather than on every
   packet. */
static int
body_has_hello(const unsigned char *body, int bodylen)
{
    int i = 0;
    while(i < bodylen) {
        int type = body[i];
        if(type == MESSAGE_PAD1) {
            i++;
            continue;
        }
        if(i + 2 > bodylen)
            break;
        if(type == MESSAGE_HELLO)
            return 1;
        i += 2 + body[i + 1];
    }
    return 0;
}

int
add_hmac(struct buffered *buf, struct interface *ifp,
         unsigned char *packet_header)
{
    int hmaclen;
    int i = buf->len;
    unsigned char *dst = buf->sin6.sin6_addr.s6_addr;
    unsigned char *src;

    if(ifp->numll < 1) {
        fprintf(stderr, "add_hmac: no link-local address.\n");
        return -1;
    }
    src = ifp->ll[0];

    if(buf->len + 2 + MAX_DIGEST_LEN + 2 + MAX_DIGEST_LEN > buf->size) {
        fprintf(stderr, "Buffer overflow in add_hmac.\n");
        return -1;
    }

    /* On Hellos, emit the trust material; other packets carry only the MAC and
       verify against the receiver's caches. */
    if(ifp->key->type == AUTH_TYPE_ED25519 && body_has_hello(buf->buf, buf->len)) {
        if(x509_mode()) {
            /* X.509: distribute the cert (fragmented) and bind the ephemeral
               key with a SIG_SESSION on every Hello. The cert goes out either
               periodically (push, the default) or only when a peer has asked
               for it (pull), plus any CERT_REQUESTs we owe for peers we can't
               yet authenticate. */
            int slen;
            if(cert_pull_enabled) {
                if(cert_serve_due &&
                   (cert_served_at == 0 ||
                    now.tv_sec - cert_served_at >= CERT_SERVE_INTERVAL)) {
                    if(emit_cert_frags(buf, &i) < 0)
                        return -1;
                    cert_serve_due = 0;
                    cert_served_at = now.tv_sec;
                }
                i = emit_cert_requests(buf, i);
            } else {
                static unsigned int hello_count = 0;
                hello_count++;
                if(hello_count <= 3 || hello_count % 8 == 0) {
                    if(emit_cert_frags(buf, &i) < 0)
                        return -1;
                }
            }
            slen = build_sig_session(ifp->key, buf->buf + i + 2);
            if(slen < 0)
                return -1;
            buf->buf[i++] = MESSAGE_SIG_SESSION;
            buf->buf[i++] = slen;
            i += slen;
        } else if(own_cert_set && ephemeral_enabled) {
            /* Minimal-cert ephemeral chain (phase 2b). */
            int certlen = build_sig_cert(ifp->key, buf->buf + i + 2);
            if(certlen < 0)
                return -1;
            buf->buf[i++] = MESSAGE_SIG_CERT;
            buf->buf[i++] = certlen;
            i += certlen;
        }
    }

    if(ifp->key->type == AUTH_TYPE_ED25519)
        hmaclen = sign_ed25519(src, dst, packet_header,
                               buf->buf, buf->len, ifp->key,
                               buf->buf + i + 2);
    else
        hmaclen = compute_hmac(src, dst, packet_header,
                               buf->buf, buf->len, ifp->key,
                               buf->buf + i + 2);
    if(hmaclen < 0)
        return -1;
    buf->buf[i++] = MESSAGE_MAC;
    buf->buf[i++] = hmaclen;
    i += hmaclen;
    return i;
}


static int
compare_hmac(const unsigned char *src, const unsigned char *dst,
             const unsigned char *packet, int bodylen,
             const unsigned char *hmac, int hmaclen,
             struct key *key)
{
    unsigned char buf[MAX_DIGEST_LEN];
    int len;

    len = compute_hmac(src, dst, packet, packet + 4, bodylen, key, buf);
    return len == hmaclen && (memcmp(buf, hmac, hmaclen) == 0);
}

/* Verify the actual Ed25519 signature over the packet, given the signer's
   public key. Returns 1 on success. */
static int
verify_ed25519_sig(const unsigned char *src, const unsigned char *dst,
                   const unsigned char *packet, int bodylen,
                   const unsigned char *sig, const unsigned char *pubkey)
{
    unsigned char *region;
    int regionlen, rc;

    region = build_signed_region(src, dst, packet, packet + 4, bodylen,
                                 &regionlen);
    if(region == NULL)
        return 0;
    rc = crypto_sign_ed25519_verify_detached(sig, region, regionlen, pubkey);
    free(region);
    return rc == 0;
}

/* Validate a SIG_CERT trailer value (the ephemeral trust chain
   long_term_pubkey || cert || eph_pubkey || eph_auth): the long-term key is
   CA-certified and not revoked, and it authorized the ephemeral key. On
   success copies the trusted ephemeral public key to eph_pubkey_return and
   returns 1. */
static int
validate_sig_cert(const unsigned char *value, int valuelen,
                  unsigned char *eph_pubkey_return)
{
    const unsigned char *pubkey = value;
    const unsigned char *cert = pubkey + ED25519_PUBKEY_LEN;
    const unsigned char *eph_pubkey = cert + ED25519_CERT_LEN;
    const unsigned char *eph_auth = eph_pubkey + ED25519_PUBKEY_LEN;
    unsigned char keyid[KEYID_LEN];

    if(valuelen != ED25519_SIGCERT_LEN)
        return 0;
    if(!ca_set) {
        debugf("CA-trust packet but no CA configured.\n");
        return 0;
    }
    /* Revocation is by identity: the long-term key's fingerprint. */
    if(compute_keyid(pubkey, keyid) != 0)
        return 0;
    if(keyid_revoked(keyid)) {
        debugf("Signature chain from revoked key id.\n");
        return 0;
    }
    /* cert = CA's signature over the long-term key. */
    if(crypto_sign_ed25519_verify_detached(cert, pubkey, ED25519_PUBKEY_LEN,
                                           ca_pubkey) != 0) {
        debugf("Certificate not signed by the configured CA.\n");
        return 0;
    }
    /* eph_auth = long-term key's authorization of the ephemeral key. */
    if(crypto_sign_ed25519_verify_detached(eph_auth, eph_pubkey,
                                           ED25519_PUBKEY_LEN, pubkey) != 0) {
        debugf("Ephemeral key not authorized by the long-term key.\n");
        return 0;
    }
    /* Cache the validated ephemeral key so later MAC-only packets from this
       session need not re-carry the chain. */
    {
        unsigned char eph_keyid[KEYID_LEN];
        if(compute_keyid(eph_pubkey, eph_keyid) == 0)
            session_upsert(eph_keyid, eph_pubkey, keyid);
    }
    memcpy(eph_pubkey_return, eph_pubkey, ED25519_PUBKEY_LEN);
    return 1;
}

/* Verify one MAC trailer value. Layouts, by length:

   V2 (CA trust): keyid || pubkey || cert || sig — the long-term key signs and
   travels with its CA certificate.

   V1 (72): keyid || sig. If a SIG_CERT in the same packet vouched for an
   ephemeral key whose fingerprint matches keyid, verify with that ephemeral
   key (phase 2b). Otherwise verify against a preconfigured trusted key
   (phase 1).

   Returns 1 on a good signature from an authorized signer, else 0. */
static int
verify_ed25519(const unsigned char *src, const unsigned char *dst,
               const unsigned char *packet, int bodylen,
               const unsigned char *value, int valuelen,
               const unsigned char *eph_pubkey, int have_eph)
{
    if(valuelen == ED25519_TRAILER_V2_LEN) {
        const unsigned char *keyid = value;
        const unsigned char *pubkey = value + KEYID_LEN;
        const unsigned char *cert = pubkey + ED25519_PUBKEY_LEN;
        const unsigned char *sig = cert + ED25519_CERT_LEN;
        unsigned char expected_keyid[KEYID_LEN];

        if(!ca_set) {
            debugf("CA-trust packet but no CA configured.\n");
            return 0;
        }
        if(keyid_revoked(keyid)) {
            debugf("Signature from revoked key id.\n");
            return 0;
        }
        if(compute_keyid(pubkey, expected_keyid) != 0 ||
           memcmp(keyid, expected_keyid, KEYID_LEN) != 0) {
            debugf("Key id does not match public key.\n");
            return 0;
        }
        if(crypto_sign_ed25519_verify_detached(cert, pubkey,
                                               ED25519_PUBKEY_LEN,
                                               ca_pubkey) != 0) {
            debugf("Certificate not signed by the configured CA.\n");
            return 0;
        }
        return verify_ed25519_sig(src, dst, packet, bodylen, sig, pubkey);
    }

    if(valuelen == ED25519_TRAILER_V1_LEN) {
        struct key *key;
        const unsigned char *cached;
        /* Ephemeral key vouched for by a SIG_CERT in this same packet... */
        if(have_eph) {
            unsigned char eph_keyid[KEYID_LEN];
            if(compute_keyid(eph_pubkey, eph_keyid) == 0 &&
               memcmp(value, eph_keyid, KEYID_LEN) == 0)
                return verify_ed25519_sig(src, dst, packet, bodylen,
                                          value + KEYID_LEN, eph_pubkey);
        }
        /* ...or an ephemeral key cached from an earlier Hello's chain. */
        cached = session_lookup(value);
        if(cached != NULL)
            return verify_ed25519_sig(src, dst, packet, bodylen,
                                      value + KEYID_LEN, cached);
        /* ...or a preconfigured trusted key (phase 1). */
        key = find_key_by_keyid(value);
        if(key == NULL) {
            debugf("Signature from unknown key id.\n");
            return 0;
        }
        return verify_ed25519_sig(src, dst, packet, bodylen,
                                  value + KEYID_LEN, ed25519_pubkey(key));
    }

    return 0;
}

#define SIG_SESSION_LEN (KEYID_LEN + ED25519_PUBKEY_LEN + ED25519_SIG_LEN)

/* X.509 first pass: reassemble any certificate fragments in the packet and
   cache the validated identity, then use a SIG_SESSION TLV to establish a
   trusted ephemeral key (verified against that identity's cached key). On
   success copies the ephemeral public key and returns 1. */
static int
process_x509_trailer(const unsigned char *packet, int packetlen, int bodylen,
                     unsigned char *eph_pubkey_return)
{
    unsigned char der[4096];
    int derlen = 0;
    int i, len;

    /* Reassemble the certificate from consecutive CERT_FRAG TLVs, and note any
       CERT_REQUEST that targets our own identity so we serve it next Hello. */
    for(i = bodylen + 4; i + 2 <= packetlen; i += len + 2) {
        len = packet[i + 1];
        if(i + len + 2 > packetlen)
            break;
        if(packet[i] == MESSAGE_CERT_FRAG) {
            if(derlen + len > (int)sizeof(der))
                continue;
            memcpy(der + derlen, packet + i + 2, len);
            derlen += len;
        } else if(packet[i] == MESSAGE_CERT_REQUEST && len == KEYID_LEN) {
            const unsigned char *ownfp = own_identity_fp();
            if(ownfp != NULL && memcmp(packet + i + 2, ownfp, KEYID_LEN) == 0)
                cert_serve_due = now.tv_sec;
        }
    }
    if(derlen > 0) {
        unsigned char pubkey[ED25519_PUBKEY_LEN], fp[KEYID_LEN];
        if(x509_validate(der, derlen, pubkey) &&
           compute_keyid(pubkey, fp) == 0 && !keyid_revoked(fp)) {
            identity_upsert(fp, pubkey);
            unwant_identity(fp);       /* we hold this cert now; stop asking */
        }
    }

    /* Bind the ephemeral key using the (now hopefully cached) identity. */
    for(i = bodylen + 4; i + 2 <= packetlen; i += len + 2) {
        len = packet[i + 1];
        if(i + len + 2 > packetlen)
            break;
        if(packet[i] == MESSAGE_SIG_SESSION && len == SIG_SESSION_LEN) {
            const unsigned char *fp = packet + i + 2;
            const unsigned char *eph_pubkey = fp + KEYID_LEN;
            const unsigned char *eph_auth = eph_pubkey + ED25519_PUBKEY_LEN;
            const unsigned char *ltpub = identity_lookup(fp);
            if(ltpub == NULL) {
                debugf("SIG_SESSION from an identity whose cert is not cached "
                       "yet.\n");
                /* Ask for it (served on our next Hello); harmless in push mode
                   where the cert arrives on its own. */
                want_identity(fp);
                continue;
            }
            if(crypto_sign_ed25519_verify_detached(eph_auth, eph_pubkey,
                                                   ED25519_PUBKEY_LEN,
                                                   ltpub) != 0) {
                debugf("Ephemeral key not authorized by the identity.\n");
                continue;
            }
            {
                unsigned char eph_keyid[KEYID_LEN];
                if(compute_keyid(eph_pubkey, eph_keyid) == 0)
                    session_upsert(eph_keyid, eph_pubkey, fp);
            }
            memcpy(eph_pubkey_return, eph_pubkey, ED25519_PUBKEY_LEN);
            return 1;
        }
    }
    return 0;
}

int
check_hmac(const unsigned char *packet, int packetlen, int bodylen,
           const unsigned char *src, const unsigned char *dst,
           struct interface *ifp)
{
    int i;
    int len;
    int rc = -1;
    int ed25519 = (ifp->key != NULL && ifp->key->type == AUTH_TYPE_ED25519);
    unsigned char eph_pubkey[ED25519_PUBKEY_LEN];
    int have_eph = 0;

    debugf("check_hmac %s -> %s\n",
           format_address(src), format_address(dst));

    /* First pass: a SIG_CERT (minimal) or CERT_FRAG+SIG_SESSION (X.509)
       trailer establishes a trusted ephemeral key for the MAC. */
    if(ed25519 && x509_mode()) {
        have_eph = process_x509_trailer(packet, packetlen, bodylen, eph_pubkey);
    } else if(ed25519) {
        for(i = bodylen + 4; i + 2 <= packetlen; i += len + 2) {
            len = packet[i + 1];
            if(i + len + 2 > packetlen)
                break;
            if(packet[i] == MESSAGE_SIG_CERT) {
                if(validate_sig_cert(packet + i + 2, len, eph_pubkey)) {
                    have_eph = 1;
                    break;
                }
            }
        }
    }

    for(i = bodylen + 4; i < packetlen; i += len + 2) {
        if(i + 2 > packetlen) {
            fprintf(stderr, "Received truncated message.\n");
            break;
        }
        len = packet[i + 1];
        if(packet[i] == MESSAGE_MAC) {
            int ok;
            if(i + len + 2 > packetlen) {
                fprintf(stderr, "Received truncated message.\n");
                return -1;
            }
            if(ed25519)
                ok = verify_ed25519(src, dst, packet, bodylen,
                                    packet + i + 2, len, eph_pubkey, have_eph);
            else
                ok = compare_hmac(src, dst, packet, bodylen,
                                  packet + i + 2, len, ifp->key);
            if(ok)
                return 1;
            rc = 0;
        }
    }
    return rc;
}
