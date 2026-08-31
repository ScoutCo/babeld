/*
Copyright (c) 2026 by Scout AI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
*/

/* OpenSSL-facing X.509 handling for Babel-SIG, kept in its own translation
   unit so the ASN.1 parsing stays out of the per-packet Ed25519 path. A
   "certificate" here is a real X.509 cert whose subject public key is
   Ed25519; validation yields the raw 32-byte key that the rest of Babel-SIG
   verifies signatures against. */

/* Trust anchor: the fleet CA certificate, in DER. Returns 1 on success. */
int x509_set_ca(const unsigned char *der, int len);

/* This node's own certificate, in DER: kept both to answer CERT_REQUESTs and
   to publish this node's identity. Returns 1 on success. */
int x509_set_own(const unsigned char *der, int len);

/* The stored own-certificate DER (for serving to peers), or NULL. */
const unsigned char *x509_own_der(int *len_return);

/* Whether to enforce notBefore/notAfter. Off until the system clock is
   trusted (timesync/GPS), so a boot-time clock cannot black-hole routing. */
void x509_set_enforce_time(int enforce);

/* Validate a peer certificate (DER) against the configured CA — chain and key
   usage always, validity window only when enforcement is on — and copy its
   raw 32-byte Ed25519 public key to pubkey_return. Returns 1 on success. */
int x509_validate(const unsigned char *der, int len,
                  unsigned char *pubkey_return);