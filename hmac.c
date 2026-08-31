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

    memcpy(value_return + o, key->keyid, KEYID_LEN);
    o += KEYID_LEN;
    if(own_cert_set) {
        memcpy(value_return + o, key->value + 32, ED25519_PUBKEY_LEN);
        o += ED25519_PUBKEY_LEN;
        memcpy(value_return + o, own_cert, ED25519_CERT_LEN);
        o += ED25519_CERT_LEN;
    }
    rc = crypto_sign_ed25519_detached(value_return + o, NULL,
                                      region, regionlen, key->value);
    free(region);
    if(rc != 0)
        return -1;
    return o + ED25519_SIG_LEN;
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

    if(buf->len + 2 + MAX_DIGEST_LEN > buf->size) {
        fprintf(stderr, "Buffer overflow in add_hmac.\n");
        return -1;
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

/* Verify one Ed25519 trailer value. Two layouts are accepted:

   V2 (CA trust): keyid || pubkey || cert || sig. The public key travels in
   the packet and is trusted because `cert` is the CA's signature over it, so
   no per-peer configuration is needed. keyid must match the public key (it is
   its fingerprint, and the unit of revocation).

   V1 (preconfigured): keyid || sig, verified against a trusted key looked up
   by keyid.

   Returns 1 on a good signature from an authorized signer, else 0. */
static int
verify_ed25519(const unsigned char *src, const unsigned char *dst,
               const unsigned char *packet, int bodylen,
               const unsigned char *value, int valuelen)
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
        /* The keyid must be the fingerprint of the carried public key, so a
           revocation by keyid cannot be dodged by presenting a mismatched
           pubkey. */
        if(compute_keyid(pubkey, expected_keyid) != 0 ||
           memcmp(keyid, expected_keyid, KEYID_LEN) != 0) {
            debugf("Key id does not match public key.\n");
            return 0;
        }
        /* The certificate is the CA's signature over the public key. */
        if(crypto_sign_ed25519_verify_detached(cert, pubkey,
                                               ED25519_PUBKEY_LEN,
                                               ca_pubkey) != 0) {
            debugf("Certificate not signed by the configured CA.\n");
            return 0;
        }
        return verify_ed25519_sig(src, dst, packet, bodylen, sig, pubkey);
    }

    if(valuelen == ED25519_TRAILER_V1_LEN) {
        struct key *key = find_key_by_keyid(value);
        if(key == NULL) {
            debugf("Signature from unknown key id.\n");
            return 0;
        }
        return verify_ed25519_sig(src, dst, packet, bodylen,
                                  value + KEYID_LEN, ed25519_pubkey(key));
    }

    return 0;
}

int
check_hmac(const unsigned char *packet, int packetlen, int bodylen,
           const unsigned char *src, const unsigned char *dst,
           struct interface *ifp)
{
    int i = bodylen + 4;
    int len;
    int rc = -1;
    int ed25519 = (ifp->key != NULL && ifp->key->type == AUTH_TYPE_ED25519);

    debugf("check_hmac %s -> %s\n",
           format_address(src), format_address(dst));
    while(i < packetlen) {
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
                                    packet + i + 2, len);
            else
                ok = compare_hmac(src, dst, packet, bodylen,
                                  packet + i + 2, len, ifp->key);
            if(ok)
                return 1;
            rc = 0;
        }
        i += len + 2;
    }
    return rc;
}
