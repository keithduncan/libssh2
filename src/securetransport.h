/* Copyright (C) 2013 Keith Duncan */

#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import "CommonBigNum.h"

#define _libssh2_random(buf, len) SecRandomCopyBytes(kSecRandomDefault, len, buf)

#define SHA_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH

#define libssh2_sha1_ctx CC_SHA1_CTX
#define libssh2_sha1_init(ctx) CC_SHA1_Init(ctx)
#define libssh2_sha1_update(ctx, data, len) CC_SHA1_Update(&ctx, data, len)
#define libssh2_sha1_final(ctx, out) CC_SHA1_Final(out, &ctx)
#define libssh2_sha1(data, datalen, out) CC_SHA1(data, datalen, out)

#define LIBSSH2_MD5 1
#define MD5_DIGEST_LENGTH CC_MD5_DIGEST_LENGTH

#define libssh2_md5_ctx CC_MD5_CTX
#define libssh2_md5_init(ctx) CC_MD5_Init(ctx)
#define libssh2_md5_update(ctx, data, len) CC_MD5_Update(&ctx, data, len)
#define libssh2_md5_final(ctx, out) CC_MD5_Final(out, &ctx)
#define libssh2_md5(data, datalen, out) CC_MD5(data, datalen, out)

#define LIBSSH2_HMAC_RIPEMD 0

#define libssh2_hmac_ctx CCHmacContext
#define libssh2_hmac_sha1_init(ctx, key, keylen) CCHmacInit(ctx, kCCHmacAlgSHA1, key, keylen)
#define libssh2_hmac_md5_init(ctx, key, keylen) CCHmacInit(ctx, kCCHmacAlgMD5, key, keylen)
//#define libssh2_hmac_ripemd160_init(ctx, key, keylen)
#define libssh2_hmac_update(ctx, data, datalen) CCHmacUpdate(&ctx, data, datalen)
#define libssh2_hmac_final(ctx, data) CCHmacFinal(&ctx, data)
#define libssh2_hmac_cleanup(ctx)

#define libssh2_crypto_init()
#define libssh2_crypto_exit()

#define _libssh2_init_aes_ctr()

#define LIBSSH2_RSA 1
#define LIBSSH2_DSA 0

typedef struct {

} libssh2_rsa_ctx;

#define _libssh2_rsa_free(rsactx)

typedef struct {

} libssh2_dsa_ctx;

#define _libssh2_dsa_free(dsactx)

typedef struct {

} _libssh2_cipher_ctx;

#define LIBSSH2_AES 1
#define LIBSSH2_AES_CTR 1
#define LIBSSH2_BLOWFISH 1
#define LIBSSH2_RC4 1
#define LIBSSH2_CAST 1
#define LIBSSH2_3DES 1

#define _libssh2_cipher_type(name) void *name

#define _libssh2_cipher_aes256
#define _libssh2_cipher_aes192
#define _libssh2_cipher_aes128

#define _libssh2_cipher_aes256ctr
#define _libssh2_cipher_aes192ctr
#define _libssh2_cipher_aes128ctr

#define _libssh2_cipher_blowfish
#define _libssh2_cipher_arcfour
#define _libssh2_cipher_cast5
#define _libssh2_cipher_3des

#define _libssh2_cipher_dtor(ctx)

typedef void *_libssh2_bn_ctx;
#define _libssh2_bn_ctx_new() NULL
#define _libssh2_bn_ctx_free(bnctx)

#define _libssh2_bn struct _CCBigNumRef
#define _libssh2_bn_init() CCCreateBigNum(NULL)
#define _libssh2_bn_rand(bn, bits, top, bottom) \
do {\
  if (bn != NULL) CCBigNumFree(bn);\
  bn = CCBigNumCreateRandom(NULL, bits, top, bottom);\
} while (0)
#define _libssh2_bn_mod_exp(r, a, power, modulus, ctx) CCBigNumModExp(r, a, power, modulus)

#define _libssh2_bn_set_word(bn, val) \
do {\
  CCBigNumClear(bn);\
  CCBigNumAddI(bn, bn, val);\
} while (0)

#define _libssh2_bn_from_bin(bn, len, val) CCBigNumFromData(NULL, val, len)
#define _libssh2_bn_to_bin(bn, val) CCBigNumToData(NULL, bn, val)

#define _libssh2_bn_bytes(bn) CCBigNumByteCount(bn)
#define _libssh2_bn_bits(bn) CCBigNumBitCount(bn)

#define _libssh2_bn_free(bn) CCBigNumFree(bn)
