/* Copyright (C) 2013 Keith Duncan */

#import "securetransport.h"

#include "libssh2_priv.h"

#pragma mark - RSA

int _libssh2_rsa_new(libssh2_rsa_ctx **rsa,
                     unsigned char const *edata,
                     unsigned long elen,
                     unsigned char const *ndata,
                     unsigned long nlen,
                     unsigned char const *ddata,
                     unsigned long dlen,
                     unsigned char const *pdata,
                     unsigned long plen,
                     unsigned char const *qdata,
                     unsigned long qlen,
                     unsigned char const *e1data,
                     unsigned long e1len,
                     unsigned char const *e2data,
                     unsigned long e2len,
                     unsigned char const *coeffdata,
                     unsigned long coefflen) {
  return 0;
}

int _libssh2_rsa_new_private(libssh2_rsa_ctx **rsa,
                             LIBSSH2_SESSION *session,
                             char const *filename,
                             unsigned char const *passphrase) {
  return 0;
}

int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                             unsigned char const *sig,
                             unsigned long sig_len,
                             unsigned char const *m,
                             unsigned long m_len) {
  return 0;
}

int _libssh2_rsa_sha1_sign(LIBSSH2_SESSION *session,
                           libssh2_rsa_ctx *rsactx,
                           unsigned char const *hash,
                           size_t hash_len,
                           unsigned char **signature,
                           size_t *signature_len) {
  return 0;
}

#pragma mark - DSA

int _libssh2_dsa_new(libssh2_dsa_ctx **dsa,
                     unsigned char const *pdata,
                     unsigned long plen,
                     unsigned char const *qdata,
                     unsigned long qlen,
                     unsigned char const *gdata,
                     unsigned long glen,
                     unsigned char const *ydata,
                     unsigned long ylen,
                     unsigned char const *x,
                     unsigned long x_len) {
  return 0;
}

int _libssh2_dsa_new_private(libssh2_dsa_ctx **dsa,
                             LIBSSH2_SESSION *session,
                             char const *filename,
                             unsigned char const *passphrase) {
  return 0;
}

int _libssh2_dsa_sha1_verify(libssh2_dsa_ctx *dsactx,
                             unsigned char const *sig,
                             unsigned char const *m,
                             unsigned long m_len) {
  return 0;
}

int _libssh2_dsa_sha1_sign(libssh2_dsa_ctx *dsactx,
                           unsigned char const *hash,
                           unsigned long hash_len,
                           unsigned char *sig) {
  return 0;
}

#pragma mark - Ciphers

int _libssh2_cipher_init(_libssh2_cipher_ctx *h,
                         _libssh2_cipher_type(algo),
                         unsigned char *iv,
                         unsigned char *secret,
                         int encrypt) {
  return 0;
}

int _libssh2_cipher_crypt(_libssh2_cipher_ctx *ctx,
                          _libssh2_cipher_type(algo),
                          int encrypt,
                          unsigned char *block,
                          size_t blocksize) {
  return 0;
}

#pragma mark - Private Public Keys

int _libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                              unsigned char **method,
                              size_t *method_len,
                              unsigned char **pubkeydata,
                              size_t *pubkeydata_len,
                              char const *privatekey,
                              char const *passphrase) {
  return 0;
}
