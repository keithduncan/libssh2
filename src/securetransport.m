/* Copyright (C) 2013 Keith Duncan */

#import "securetransport.h"

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <Security/SecAsn1Coder.h>

#include "libssh2_priv.h"

static const CSSM_GUID _libssh2_cdsa_guid = { 0xA606, 0x71CF, 0x8F03, { 0x48, 0xE0, 0xAF, 0xE8, 0x8D, 0x20, 0x86, 0x16 } }; // generated using `uuidgen`
static CSSM_CSP_HANDLE _libssh2_cdsa_csp = CSSM_INVALID_HANDLE;

static void *_libssh2_cdsa_malloc(CSSM_SIZE size, void *allocref) {
  return malloc(size);
}

static void _libssh2_cdsa_free(void *memory, void *allocref) {
  free(memory);
}

static void *_libssh2_cdsa_realloc(void *memory, CSSM_SIZE size, void *allocref) {
  return realloc(memory, size);
}

static void *_libssh2_cdsa_calloc(uint32_t number, CSSM_SIZE size, void *allocref) {
  return calloc(number, size);
}

static const CSSM_API_MEMORY_FUNCS _libssh2_cdsa_memory_functions = {
	_libssh2_cdsa_malloc,
	_libssh2_cdsa_free,
	_libssh2_cdsa_realloc,
  _libssh2_cdsa_calloc,
  NULL,
};

static void attachToModules(void) {
  CSSM_VERSION version = {
    .Major = 2,
    .Minor = 0,
  };
  CSSM_PVC_MODE pvcPolicy = CSSM_PVC_NONE;
  CSSM_RETURN error = CSSM_Init(&version, CSSM_PRIVILEGE_SCOPE_PROCESS, &_libssh2_cdsa_guid, CSSM_KEY_HIERARCHY_NONE, &pvcPolicy, NULL);
  if (error != CSSM_OK) {
    return;
  }

  error = CSSM_ModuleLoad(&gGuidAppleCSP, CSSM_KEY_HIERARCHY_NONE, NULL, NULL);
  if (error != CSSM_OK) {
    return;
  }

  error = CSSM_ModuleAttach(&gGuidAppleCSP, &version, &_libssh2_cdsa_memory_functions, 0, CSSM_SERVICE_CSP, 0, CSSM_KEY_HIERARCHY_NONE, NULL, 0, NULL, &_libssh2_cdsa_csp);
  if (error != CSSM_OK) {
    return;
  }
}

static void detachFromModules(void) {
  // FIXME
}

void libssh2_crypto_init(void) {
  attachToModules();
}

void libssh2_crypto_exit(void) {
  detachFromModules();
}

#pragma mark - RSA

static int _libssh2_rsa_new_from_pkcs1_raw_blob(libssh2_rsa_ctx **rsa, NSData *blob) {
  CSSM_KEY privateKey = {
    .KeyHeader = {
      .HeaderVersion = CSSM_KEYHEADER_VERSION,
      .BlobType = CSSM_KEYBLOB_RAW,
      .Format = CSSM_KEYBLOB_RAW_FORMAT_PKCS1,
      .AlgorithmId = CSSM_ALGID_RSA,
      .KeyClass = CSSM_KEYCLASS_PRIVATE_KEY,
      .KeyUsage = CSSM_KEYUSE_ANY,
    },
    .KeyData = {
      .Length = [blob length],
      .Data = (uint8_t *)[blob bytes],
    },
  };

  CSSM_KEY_SIZE keySize = {};
  CSSM_RETURN error = CSSM_QueryKeySizeInBits(_libssh2_cdsa_csp, CSSM_INVALID_HANDLE, &privateKey, &keySize);
  if (error != CSSM_OK) {
    return 1;
  }
  privateKey.KeyHeader.LogicalKeySizeInBits = keySize.LogicalKeySizeInBits;

  *rsa = malloc(sizeof(privateKey));

  memmove(&((*rsa)->KeyHeader), &privateKey.KeyHeader, sizeof(privateKey.KeyHeader));

  (*rsa)->KeyData.Length = privateKey.KeyData.Length;
  (*rsa)->KeyData.Data = malloc(privateKey.KeyData.Length);
  memmove((*rsa)->KeyData.Data, privateKey.KeyData.Data, privateKey.KeyData.Length);

  return 0;
}

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

typedef enum {
  RSA_Version_TwoPrime = 0,
  RSA_Version_Multi = 1,
} RSA_Version;

static const SecAsn1Template _libssh2_RSA_private_key_PKCS1_template[] = {
  { .kind = SEC_ASN1_SEQUENCE, .size = sizeof(_libssh2_RSA_private_key_PKCS1) },
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
  /*
      Convert the raw numeric binary data to PKCS#1 format, create a CSSM_KEY
      with the result.
   */

   uint8_t version = RSA_Version_TwoPrime;

  _libssh2_RSA_private_key_PKCS1 privateKeyData = {
    .version = {
      .Length = sizeof(version),
      .Data = &version,
    },
    .modulus = {
      .Length = nlen,
      .Data = (uint8_t *)ndata,
    },
    .publicExponent = {
      .Length = elen,
      .Data = (uint8_t *)edata,
    },
    .privateExponent = {
      .Length = dlen,
      .Data = (uint8_t *)ddata,
    },
    .prime1 = {
      .Length = plen,
      .Data = (uint8_t *)pdata,
    },
    .prime2 = {
      .Length = qlen,
      .Data = (uint8_t *)qdata,
    },
    .exponent1 = {
      .Length = e1len,
      .Data = (uint8_t *)e1data,
    },
    .exponent2 = {
      .Length = e2len,
      .Data = (uint8_t *)e2data,
    },
    .coefficient = {
      .Length = coefflen,
      .Data = (uint8_t *)coeffdata,
    },
  };

  SecAsn1CoderRef coder = NULL;
  OSStatus error = SecAsn1CoderCreate(&coder);
  if (error != noErr) {
    return 1;
  }

  CSSM_DATA keyData = {};
  error = SecAsn1EncodeItem(coder, &privateKeyData, _libssh2_RSA_private_key_PKCS1_template, &keyData);
  if (error != noErr) {
    SecAsn1CoderRelease(coder);
    return 1;
  }

  int createKey = _libssh2_rsa_new_from_pkcs1_raw_blob(rsa, [NSData dataWithBytes:keyData.Data length:keyData.Length]);

  SecAsn1CoderRelease(coder);

  return createKey;
}

static NSData *_libssh2_pkcs1_header(void) {
  return [@"-----BEGIN RSA PRIVATE KEY-----" dataUsingEncoding:NSUTF8StringEncoding];
}
static NSData *_libssh2_pkcs1_footer(void) {
  return [@"-----END RSA PRIVATE KEY-----" dataUsingEncoding:NSUTF8StringEncoding];
}

static NSData *_libssh2_pkcs8_header(void) {
  return [@"-----BEGIN PRIVATE KEY-----" dataUsingEncoding:NSUTF8StringEncoding];
}
static NSData *_libssh2_pkcs8_footer(void) {
  return [@"-----END PRIVATE KEY-----" dataUsingEncoding:NSUTF8StringEncoding];
}

static NSData *_libssh2_pkcs8_encrypted_header(void) {
  return [@"-----BEGIN ENCRYPTED PRIVATE KEY-----" dataUsingEncoding:NSUTF8StringEncoding];
}
static NSData *_libssh2_pkcs8_encrypted_footer(void) {
  return [@"-----END ENCRYPTED PRIVATE KEY-----" dataUsingEncoding:NSUTF8StringEncoding];
}

static BOOL dataReadNext(NSData *data, NSUInteger *cursor, NSData *match) {
  NSRange range = [data rangeOfData:match options:NSDataSearchAnchored range:NSMakeRange(*cursor, [data length] - *cursor)];
  if (range.location == NSNotFound) {
    return NO;
  }

  *cursor = NSMaxRange(range);
  return YES;
}

static BOOL dataReadNewline(NSData *data, NSUInteger *cursor) {
  return dataReadNext(data, cursor, [@"\n" dataUsingEncoding:NSUTF8StringEncoding]) || dataReadNext(data, cursor, [@"\r\n" dataUsingEncoding:NSUTF8StringEncoding]);
}

static NSData *dataReadUptoIncluding(NSData *data, NSUInteger *cursor, NSData *suffix) {
  NSRange suffixRange = [data rangeOfData:suffix options:0 range:NSMakeRange(*cursor, [data length] - *cursor)];
  if (suffixRange.location == NSNotFound) {
    return nil;
  }

  NSUInteger newCursor = NSMaxRange(suffixRange);
  NSData *subdata = [data subdataWithRange:NSMakeRange(*cursor, newCursor - *cursor)];
  *cursor = newCursor;

  return subdata;
}

static NSArray *dataReadHeaders(NSData *data, NSUInteger *cursor) {
  NSData *headersData = dataReadUptoIncluding(data, cursor, [@"\n\n" dataUsingEncoding:NSUTF8StringEncoding]);
  if (headersData == nil) {
    headersData = dataReadUptoIncluding(data, cursor, [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding]);
  }
  if (headersData == nil) {
    return nil;
  }

  NSMutableArray *headers = [NSMutableArray array];

  NSUInteger headersCursor = 0;
  while (!dataReadNewline(headersData, &headersCursor)) {
    if (headersCursor == [headersData length]) {
      break;
    }

    NSData *currentHeader = dataReadUptoIncluding(headersData, &headersCursor, [@"\n" dataUsingEncoding:NSUTF8StringEncoding]);
    if (currentHeader == nil) {
      break;
    }
    [headers addObject:currentHeader];
  }

  return headers;
}

static NSCharacterSet *base64CharacterSet(void) {
  static NSCharacterSet *characterSet = nil;
  static dispatch_once_t characterSetPredicate = 0;
  dispatch_once(&characterSetPredicate, ^{
    NSMutableCharacterSet *newCharacterSet = [[NSMutableCharacterSet alloc] init];
    [newCharacterSet addCharactersInString:@"abcdefghijklmnopqrstuvwxyz"];
    [newCharacterSet addCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZ"];
    [newCharacterSet addCharactersInString:@"0123456789"];
    [newCharacterSet addCharactersInString:@"+/="];
    characterSet = newCharacterSet;
  });
  return characterSet;
}

static NSData *dataReadCharactersFromSet(NSData *data, NSUInteger *cursor, NSCharacterSet *characterSet) {
  NSRange subrange = NSMakeRange(NSNotFound, 0);

  uint8_t const *bytes = [data bytes];
  NSUInteger length = [data length];

  while (*cursor < length) {
    uint8_t character = *(bytes + *cursor);
    if (![characterSet characterIsMember:character]) {
      break;
    }

    if (subrange.location == NSNotFound) {
      subrange.location = *cursor;
      subrange.length = 1;
    }
    else {
      subrange.length = subrange.length + 1;
    }

    *cursor = NSMaxRange(subrange);
  }

  if (subrange.location == NSNotFound) {
    return nil;
  }

  return [data subdataWithRange:subrange];
}

static NSData *dataReadBase64Line(NSData *data, NSUInteger *cursor) {
  NSUInteger originalCursor = *cursor;

  NSData *characters = dataReadCharactersFromSet(data, cursor, base64CharacterSet());

  if (!dataReadNewline(data, cursor)) {
    *cursor = originalCursor;
    return nil;
  }

  return characters;
}

static int _libssh2_decode_pem(NSData *pemData, NSData *header, NSData *footer, NSArray **headers, NSData **binary) {
  NSUInteger cursor = 0;

  if (!dataReadNext(pemData, &cursor, header)) {
    return 1;
  }
  if (!dataReadNewline(pemData, &cursor)) {
    return 1;
  }

  *headers = dataReadHeaders(pemData, &cursor);

  NSMutableData *base64Data = [NSMutableData data];
  NSData *base64Line = nil;
  while ((base64Line = dataReadBase64Line(pemData, &cursor))) {
    [base64Data appendData:base64Line];
  }
  if ([base64Data length] == 0) {
    return 1;
  }

  *binary = [[NSData alloc] initWithBase64EncodedData:base64Data options:0];

  if (!dataReadNext(pemData, &cursor, footer)) {
    return 1;
  }

  return 0;
}

static int _libssh2_rsa_new_pem_encoded_pkcs1_key(libssh2_rsa_ctx **rsa, LIBSSH2_SESSION *session, NSData *keyData, NSString *passphrase) {
  NSArray *headers = nil;
  NSData *binary = nil;
  int decode = _libssh2_decode_pem(keyData, _libssh2_pkcs1_header(), _libssh2_pkcs1_footer(), &headers, &binary);
  if (decode != 0) {
    return decode;
  }

  if ([headers count] != 0) {
    return 1;
  }

  return _libssh2_rsa_new_from_pkcs1_raw_blob(rsa, binary);
}

static int _libssh2_rsa_new_pem_encoded_pkcs8_key(libssh2_rsa_ctx **rsa, LIBSSH2_SESSION *session, NSData *keyData, NSString *passphrase) {
  return 1;
}

/*
    Create an RSA key from a PEM file.

    The key data may be a PKCS#1 key (non-encrypted or encrypted [PEM headers
    will indicate the parameters]) or a PKCS#8 key.

    PKCS#1 keys are bounded by the header/footer

      For both non encrypted and encrypted keys
      -----BEGIN RSA PRIVATE KEY-----
      -----END RSA PRIVATE KEY-----

    PKCS#8 keys are bounded by the header/footer

      For a non-encrypted key
      -----BEGIN PRIVATE KEY-----
      -----END PRIVATE KEY-----

      For an encrypted key
      -----BEGIN ENCRYPTED PRIVATE KEY-----
      -----END ENCRYPTED PRIVATE KEY-----

    Note that a PKCS#8 key may not be an RSA key, it may be another key type,
    the key type must be checked.

    In both PKCS#1 and PKCS#8, the general form of the object is:

      key = header newline [ *parameter newline ] 1*key-data footer
      newline = LF | ( CR LF )
      CR = <US-ASCII CR, carriage return (13)>
      LF = <US-ASCII LF, linefeed (10)>
      parameter = key ': ' value newline
      key-data = 1*( ALPHA | DIGIT | '+' | '/' | '=' ) newline
      UPALPHA = <any US-ASCII uppercase letter "A".."Z">
      LOALPHA = <any US-ASCII lowercase letter "a".."z">
      ALPHA = UPALPHA | LOALPHA
      DIGIT = <any US-ASCII digit "0".."9">

    keyData    - Will not be NULL.
    passphrase - May be NULL, not covariant with whether the key is encrypted or
                 not.

    Returns 0 if the key was populated, 1 otherwise.
 */
static int _libssh2_rsa_new_pem_encoded_key(libssh2_rsa_ctx **rsa, LIBSSH2_SESSION *session, NSData *keyData, NSString *passphrase) {
  if (_libssh2_rsa_new_pem_encoded_pkcs1_key(rsa, session, keyData, passphrase) == 0) {
    return 0;
  }

  if (_libssh2_rsa_new_pem_encoded_pkcs8_key(rsa, session, keyData, passphrase) == 0) {
    return 0;
  }

  return 1;
}

/*
    See the extensive documentation for `_libssh2_rsa_new_pem_encoded_key`.

    Handles DER encoded PKCS#8 keys, there is no outer PEM encoding to unwrap.
 */
static int _libssh2_rsa_new_der_encoded_key(libssh2_rsa_ctx **rsa, LIBSSH2_SESSION *session, NSData *keyData, NSString *passphrase) {
  return 1;
}

/*
    Create an RSA key from a file.

    From libgcrypt.c, it only handles PEM encoded non-encrypted PKCS#1 keys.

    From openssl.c, the file data is passed into PEM_read_bio_RSAPrivateKey,
    this function can handle PKCS#1 encoded keys (both non-encrypted [standard]
    and encrypted [openssl extension] with the encryption details in the PEM
    object header), and PKCS#8 encoded keys (again both non-encrypted and
    encrypted - this time at the PKCS#8 layer).

    PKCS#1 keys will always be PEM encoded, PKCS#8 keys may be PEM or DER
    encoded.

    This function effectively has to duplicate the functionality of
    `SecItemImport` but without a keychain.

    See `impExpImportRawKey` for non-encrypted PKCS#1, and
    `impExpWrappedKeyOpenSslExport` for encrypted PKCS#1, to create the
    CSSM_Key.

    See `impExpPkcs8Import` and `impExpImportKeyCommon` in Security.framework
    for the CSSM routines to create the CSSM_Key for PKCS#8.

    Returns 0 if the key is created, 1 otherwise.
*/
int _libssh2_rsa_new_private(libssh2_rsa_ctx **rsa, LIBSSH2_SESSION *session, char const *filename, unsigned char const *passphrase) {
  @autoreleasepool {
    NSData *keyData = [NSData dataWithContentsOfFile:@(filename) options:0 error:NULL];
    if (keyData == NULL) {
      return 1;
    }

    // UTF-8 may not be the correct encoding here, but a good guess given that
    // it covers ASCII too.
    NSString *nsPassphrase = passphrase ? [NSString stringWithCString:(char const *)passphrase encoding:NSUTF8StringEncoding] : NULL;

    return _libssh2_rsa_new_pem_encoded_key(rsa, session, keyData, nsPassphrase);
  }
}

int _libssh2_rsa_free(libssh2_rsa_ctx *rsactx) {
  // Why isn't this using CSSM_FreeKey?

  bzero(rsactx->KeyData.Data, rsactx->KeyData.Length);
  free(rsactx->KeyData.Data);

  bzero(rsactx, sizeof(CSSM_KEY)); // should probably _actually_ zero the data
  free(rsactx);

  return 0;
}

extern OSStatus SecKeyCreateWithCSSMKey(const CSSM_KEY *key, SecKeyRef* keyRef);
extern const char *cssmErrorString(CSSM_RETURN error);

int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsactx,
                             unsigned char const *sig,
                             unsigned long sig_len,
                             unsigned char const *m,
                             unsigned long m_len) {
  CSSM_CC_HANDLE context = CSSM_INVALID_HANDLE;
  CSSM_RETURN error = CSSM_CSP_CreateSignatureContext(_libssh2_cdsa_csp, CSSM_ALGID_RSA, NULL, rsactx, &context);
  if (error != CSSM_OK) {
    return 1;
  }

  CSSM_DATA plaintext = {
    .Length = m_len,
    .Data = (uint8_t *)m,
  };

  CSSM_DATA signatureData = {
    .Length = sig_len,
    .Data = (uint8_t *)sig,
  };

  error = CSSM_VerifyData(context, &plaintext, 1, CSSM_ALGID_NONE, &signatureData);

  CSSM_DeleteContext(context);

  if (error != CSSM_OK) {
    return 1;
  }

  return 0;
}

int _libssh2_rsa_sha1_sign(LIBSSH2_SESSION *session,
                           libssh2_rsa_ctx *rsactx,
                           unsigned char const *hash,
                           size_t hash_len,
                           unsigned char **signature,
                           size_t *signature_len) {
  CSSM_ACCESS_CREDENTIALS const *credentials = NULL;

  SecKeyRef key = NULL;
  OSStatus keyError = SecKeyCreateWithCSSMKey(rsactx, &key);
  if (keyError != errSecSuccess) {
    return 1;
  }

  keyError = SecKeyGetCredentials(key, CSSM_ACL_AUTHORIZATION_SIGN, kSecCredentialTypeDefault, &credentials);
  if (keyError != errSecSuccess) {
    return 1;
  }

  CSSM_CC_HANDLE context = CSSM_INVALID_HANDLE;
  CSSM_RETURN error = CSSM_CSP_CreateSignatureContext(_libssh2_cdsa_csp, CSSM_ALGID_RSA, credentials, rsactx, &context);
  if (error != CSSM_OK) {
    return 1;
  }

  CSSM_CONTEXT_ATTRIBUTE blindingAttribute = {
    .AttributeType = CSSM_ATTRIBUTE_RSA_BLINDING,
    .AttributeLength = sizeof(uint32),
    .Attribute.Uint32 = 1,
  };
  error = CSSM_UpdateContextAttributes(context, 1, &blindingAttribute);
  if (error != CSSM_OK) {
    return 1;
  }

  CSSM_DATA plaintext = {
    .Length = hash_len,
    .Data = (uint8_t *)hash,
  };

  CSSM_DATA signatureData = {};

  error = CSSM_SignData(context, &plaintext, 1, CSSM_ALGID_NONE, &signatureData);

  CSSM_DeleteContext(context);

  if (error != CSSM_OK) {
    return 1;
  }

  *signature_len = signatureData.Length;
  *signature = signatureData.Data;

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
