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

/* Widest trailer value across all auth types. HMAC-SHA256 is 32; an Ed25519
   trailer is KEYID_LEN (8) + a 64-byte signature = 72. */
#define MAX_DIGEST_LEN 72

/* Ed25519 sizes, matching libsodium's crypto_sign_ed25519. */
#define ED25519_PUBKEY_LEN 32
#define ED25519_SECKEY_LEN 64
#define ED25519_SIG_LEN 64

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
