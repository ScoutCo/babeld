/*
Copyright (c) 2026 by Scout AI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

#include "x509.h"

#define ED25519_PUBKEY_LEN 32

static X509_STORE *ca_store = NULL;
static X509 *own_cert = NULL;
static unsigned char *own_der = NULL;
static int own_der_len = 0;
static int enforce_time = 0;

int
x509_set_ca(const unsigned char *der, int len)
{
    const unsigned char *p = der;
    X509 *ca = d2i_X509(NULL, &p, len);
    if(ca == NULL) {
        fprintf(stderr, "x509: could not parse CA certificate.\n");
        return 0;
    }
    if(ca_store == NULL)
        ca_store = X509_STORE_new();
    if(ca_store == NULL) {
        X509_free(ca);
        return 0;
    }
    if(X509_STORE_add_cert(ca_store, ca) != 1) {
        fprintf(stderr, "x509: could not add CA to the trust store.\n");
        X509_free(ca);
        return 0;
    }
    X509_free(ca); /* the store took a reference */
    return 1;
}

int
x509_set_own(const unsigned char *der, int len)
{
    const unsigned char *p = der;
    X509 *cert = d2i_X509(NULL, &p, len);
    if(cert == NULL) {
        fprintf(stderr, "x509: could not parse own certificate.\n");
        return 0;
    }
    if(own_cert != NULL)
        X509_free(own_cert);
    own_cert = cert;
    free(own_der);
    own_der = malloc(len);
    if(own_der == NULL) {
        own_der_len = 0;
        return 0;
    }
    memcpy(own_der, der, len);
    own_der_len = len;
    return 1;
}

const unsigned char *
x509_own_der(int *len_return)
{
    *len_return = own_der_len;
    return own_der;
}

void
x509_set_enforce_time(int enforce)
{
    enforce_time = enforce;
}

int
x509_own_pubkey(unsigned char *pub_return)
{
    EVP_PKEY *pkey;
    size_t rawlen = ED25519_PUBKEY_LEN;
    int ok = 0;

    if(own_cert == NULL)
        return 0;
    pkey = X509_get_pubkey(own_cert);
    if(pkey == NULL || EVP_PKEY_get_base_id(pkey) != EVP_PKEY_ED25519)
        goto done;
    if(EVP_PKEY_get_raw_public_key(pkey, pub_return, &rawlen) == 1 &&
       rawlen == ED25519_PUBKEY_LEN)
        ok = 1;
 done:
    EVP_PKEY_free(pkey);
    return ok;
}

int
x509_validate(const unsigned char *der, int len, unsigned char *pubkey_return)
{
    const unsigned char *p = der;
    X509 *cert;
    X509_STORE_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t rawlen = ED25519_PUBKEY_LEN;
    int ok = 0;

    if(ca_store == NULL) {
        fprintf(stderr, "x509: no CA configured.\n");
        return 0;
    }
    cert = d2i_X509(NULL, &p, len);
    if(cert == NULL) {
        fprintf(stderr, "x509: could not parse peer certificate.\n");
        return 0;
    }

    ctx = X509_STORE_CTX_new();
    if(ctx == NULL || X509_STORE_CTX_init(ctx, ca_store, cert, NULL) != 1)
        goto done;
    if(!enforce_time) {
        /* Defer validity-window checks until the clock is trusted. */
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
    }
    if(X509_verify_cert(ctx) != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "x509: certificate rejected: %s\n",
                X509_verify_cert_error_string(err));
        goto done;
    }

    pkey = X509_get_pubkey(cert);
    if(pkey == NULL || EVP_PKEY_get_base_id(pkey) != EVP_PKEY_ED25519) {
        fprintf(stderr, "x509: certificate subject key is not Ed25519.\n");
        goto done;
    }
    if(EVP_PKEY_get_raw_public_key(pkey, pubkey_return, &rawlen) != 1 ||
       rawlen != ED25519_PUBKEY_LEN) {
        fprintf(stderr, "x509: could not extract raw Ed25519 key.\n");
        goto done;
    }
    ok = 1;

 done:
    EVP_PKEY_free(pkey);
    X509_STORE_CTX_free(ctx);
    X509_free(cert);
    return ok;
}