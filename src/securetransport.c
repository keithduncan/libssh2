/* Copyright (C) 2013 Keith Duncan */

#import "securetransport.h"

#import <CoreFoundation/CoreFoundation.h>

#include "libssh2_priv.h"

#pragma mark - RSA

// <http://tools.ietf.org/html/rfc3447#appendix-A.1.2>
typedef struct {
  CSSM_DATA version; // RSA_Version_TwoPrime
  CSSM_DATA modulus;
  CSSM_DATA publicExponent;
  CSSM_DATA privateExponent;
  CSSM_DATA prime1;
  CSSM_DATA prime2;
  CSSM_DATA exponent1;
  CSSM_DATA exponent2;
  CSSM_DATA coefficient;
} _libssh2_RSA_private_key_PKCS1;

typedef enum : uint8_t {
  RSA_Version_TwoPrime = 0,
  RSA_Version_Multi = 1,
} RSA_Version;

static const SecAsn1Template _libssh2_RSA_private_key_PKCS1_template[] = {
  { .kind = SEC_ASN1_SEQUENCE, .size = sizeof(_libssh2_RSA_private_key_PKCS1_template) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_RSA_private_key_PKCS1, version) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_RSA_private_key_PKCS1, modulus) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_RSA_private_key_PKCS1, publicExponent) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_RSA_private_key_PKCS1, privateExponent) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_RSA_private_key_PKCS1, prime1) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_RSA_private_key_PKCS1, prime2) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_RSA_private_key_PKCS1, exponent1) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_RSA_private_key_PKCS1, exponent2) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_RSA_private_key_PKCS1, coefficient) },
  { },
};

/*
    Create an RSA key from the raw numeric components.

    version, e, n, d, p, q, e1, e2, coeff - positive integer in big-endian form.

    Returns 0 if the key is created, 1 otherwise.
*/
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
  CSSM_KEY privateKey = {
    .KeyHeader = {
      .HeaderVersion = 0,
      .BlobType = CSSM_KEYBLOB_RAW,
      .Format = CSSM_KEYBLOB_RAW_FORMAT_PKCS1,
      .AlgorithmId = CSSM_ALGID_RSA,
      .KeyClass = CSSM_KEYCLASS_PRIVATE_KEY,
      .LogicalKeySizeInBits = 0, // FIXME
      .KeyUsage = (CSSM_KEYUSE_SIGN | CSSM_KEYUSE_VERIFY),
    },
  };

  /*
      Convert the raw numeric binary data to PKCS#1 format, create a CSSM_KEY
      with the result.
   */

   RSA_Version version = RSA_Version_TwoPrime;

  _libssh2_RSA_private_key_PKCS1 privateKeyData = {
    .version = {
      .length = sizeof(version),
      .data = &version,
    },
    .modulus = {
      .length = nlen,
      .data = ndata,
    },
    .publicExponent = {
      .length = elen,
      .data = edata,
    },
    .privateExponent = {
      .length = dlen,
      .data = ddata,
    },
    .prime1 = {
      .length = plen,
      .data = pdata,
    },
    .prime2 = {
      .length = qlen,
      .data = qdata,
    },
    .exponent1 = {
      .length = e1len,
      .data = e1data,
    },
    .exponent2 = {
      .length = e2len,
      .data = e2data,
    },
    .coefficient = {
      .length = coefflen,
      .data = coeffdata,
    },
  };

  SecAsn1CoderRef coder = NULL;
  OSStatus error = SecAsn1CoderCreate(&coder);
  if (error != noErr) {
    return 1;
  }

  error = SecAsn1EncodeItem(coder, &privateKeyData, _libssh2_RSA_private_key_PKCS1_template, &privateKey.KeyData);

  SecAsn1CoderRelease(coder);

  if (error != noErr) {
    return 1;
  }

  *rsa = malloc(sizeof(privateKey));
  memcpy(*rsa, &privateKey, sizeof(privateKey));

  return 0;
}

/*
    Create an RSA key from a file (format?).

    Returns 0 if the key is created, 1 otherwise.
*/
int _libssh2_rsa_new_private(libssh2_rsa_ctx **rsa,
                             LIBSSH2_SESSION *session,
                             char const *filename,
                             unsigned char const *passphrase) {
  return 1;
}

int _libssh2_rsa_free(libssh2_rsa_ctx *rsactx) {
  bzero(rsactx, sizeof(CSSM_KEY)); // should probably _actually_ zero the data
  free(rsactx);
  return 0;
}

int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                             unsigned char const *sig,
                             unsigned long sig_len,
                             unsigned char const *m,
                             unsigned long m_len) {
  return 1;
}

int _libssh2_rsa_sha1_sign(LIBSSH2_SESSION *session,
                           libssh2_rsa_ctx *rsactx,
                           unsigned char const *hash,
                           size_t hash_len,
                           unsigned char **signature,
                           size_t *signature_len) {
  return 1;
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
  return 1;
}

int _libssh2_dsa_new_private(libssh2_dsa_ctx **dsa,
                             LIBSSH2_SESSION *session,
                             char const *filename,
                             unsigned char const *passphrase) {
  return 1;
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
  return 1;
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
  return 1;
}

void _libssh2_init_aes_ctr(void) {

}

#pragma mark - Private Public Keys

int _libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                              unsigned char **method,
                              size_t *method_len,
                              unsigned char **pubkeydata,
                              size_t *pubkeydata_len,
                              char const *privatekey,
                              char const *passphrase) {
  return 1;
}
