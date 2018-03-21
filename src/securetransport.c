/* Copyright (C) 2013-2018 Keith Duncan

 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#import "securetransport.h"

#include "libssh2_priv.h"
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>

#pragma mark Utilities

/*
    Create a CFDataRef object from the given path.

    path - nul terminated C string.

    Returns an initialised owned CFDataRef or NULL.
 */
static CFDataRef CreateDataFromFile(char const *path) {
  CFStringRef keyFilePath = CFStringCreateWithCString(kCFAllocatorDefault, path, kCFStringEncodingUTF8);
  CFURLRef keyFileLocation = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, keyFilePath, kCFURLPOSIXPathStyle, false);
  CFRelease(keyFilePath);

  CFReadStreamRef readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault, keyFileLocation);
  CFRelease(keyFileLocation);

  if (!CFReadStreamOpen(readStream)) {
    CFRelease(readStream);
    return NULL;
  }

  CFMutableDataRef keyData = CFDataCreateMutable(kCFAllocatorDefault, 0);

  size_t size = 1024;
  uint8_t bytes[size];

  while (1) {
    CFIndex read = CFReadStreamRead(readStream, bytes, size);
    if (read == 0) {
      break;
    }
    else if (read < 0) {
      CFRelease(keyData);
      keyData = NULL;
      break;
    }

    CFDataAppendBytes(keyData, bytes, read);
  }

  CFReadStreamClose(readStream);
  CFRelease(readStream);

  return (CFDataRef)keyData;
}

/*
    Create a CFDataRef object from the given ASN.1 object.

    itemRef - Pointer to a SecAsn1Item struct, passed byref to avoid copying.

    Returns an initialised owned CFDataRef object.
 */
static CFDataRef CreateDataFromAsn1Item(SecAsn1Item *itemRef) {
  return CFDataCreate(kCFAllocatorDefault, itemRef->Data, itemRef->Length);
}

/*
    Sign a hash with a private key.

    session       - In, non NULL when invoked from libssh2.
    key           - Initialised private key, non NULL.
    hash          - In parameter, hash bytes.
    hash_len      - In parameter, length of hash.
    signature     - Out parameter, malloced.
    signature_len - Out parameter, length of malloced signature.

    Returns true if the signature has been populated, false otherwise.
 */
static bool _libssh2_key_sign_hash(LIBSSH2_SESSION *session,
                                   SecKeyRef key,
                                   const unsigned char *hash,
                                   size_t hash_len,
                                   unsigned char **signature,
                                   size_t *signature_len) {
  assert(key != NULL);
  assert(hash != NULL);
  assert(signature != NULL);
  assert(signature_len != NULL);

  SecTransformRef transform = SecSignTransformCreate(key, NULL);
  if (transform == NULL) {
    return false;
  }

  Boolean setAttributes = true;
  setAttributes &= SecTransformSetAttribute(transform, kSecInputIsAttributeName, kSecInputIsDigest, NULL);
  setAttributes &= SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA1, NULL);

  CFDataRef inputData = CFDataCreate(kCFAllocatorDefault, hash, hash_len);
  setAttributes &= SecTransformSetAttribute(transform, kSecTransformInputAttributeName, inputData, NULL);

  if (!setAttributes) {
    CFRelease(inputData);
    CFRelease(transform);
    return false;
  }

  CFDataRef signatureData = SecTransformExecute(transform, NULL);

  CFRelease(inputData);
  CFRelease(transform);

  if (signatureData == NULL) {
    return false;;
  }

  *signature_len = CFDataGetLength(signatureData);
  *signature = session ? LIBSSH2_ALLOC(session, *signature_len) : malloc(*signature_len);
  CFDataGetBytes(signatureData, CFRangeMake(0, *signature_len), *signature);

  return true;
}

/*
    Verify a message signature with a public key.

    A sha1 hash should be computed over the message before verifying.

    key     - Initialised public key, non NULL.
    sig     - Binary data, non NULL.
    sig_len - Length of sig, non zero.
    m       - Binary message, non NULL.
    m_len   - Length of m, non zero.

    Returns true if the signature is valid, false otherwise.
 */
static bool _libssh2_key_verify_hash(SecKeyRef key,
                                     const unsigned char *sig,
                                     unsigned long sig_len,
                                     const unsigned char *m,
                                     unsigned long m_len) {
  assert(key != NULL);
  assert(sig != NULL);
  assert(m != NULL);

  CFDataRef signatureData = CFDataCreate(kCFAllocatorDefault, sig, sig_len);

  SecTransformRef transform = SecVerifyTransformCreate(key, signatureData, NULL);

  if (transform == NULL) {
    CFRelease(signatureData);
  }

  Boolean setAttributes = true;
  setAttributes &= SecTransformSetAttribute(transform, kSecInputIsAttributeName, kSecInputIsPlainText, NULL);
  setAttributes &= SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA1, NULL);

  CFDataRef message = CFDataCreate(kCFAllocatorDefault, m, m_len);
  setAttributes &= SecTransformSetAttribute(transform, kSecTransformInputAttributeName, message, NULL);

  if (!setAttributes) {
    CFRelease(message);
    CFRelease(transform);
    CFRelease(signatureData);
    return false;
  }

  CFErrorRef error = NULL;
  CFTypeRef output = SecTransformExecute(transform, &error);

  CFRelease(message);
  CFRelease(transform);
  CFRelease(signatureData);

  if (output == NULL) {
    CFRelease(error);
    return false;
  }

  return CFBooleanGetValue(output);
}

/*
    Wrap binary data in a PEM envelope.

    data   - Input data, encoded as Base64 before being wrapped.
    header - PEM header, should include any newline or PEM parameters.
    footer - PEM footer, should match the PEM header and prefix with a newline.

    Returns an initialised owned CFDataRef object or NULL.
 */
static CFDataRef _libssh2_wrap_data_in_pem(CFDataRef data, char const *header, char const *footer) {
  SecTransformRef encodeTransform = SecEncodeTransformCreate(kSecBase64Encoding, NULL);
  if (encodeTransform == NULL) {
    return NULL;
  }
  Boolean setInput = SecTransformSetAttribute(encodeTransform, kSecTransformInputAttributeName, data, NULL);
  if (!setInput) {
    CFRelease(encodeTransform);
    return NULL;
  }

  CFDataRef encodedKeyData = SecTransformExecute(encodeTransform, NULL);
  CFRelease(encodeTransform);

  if (encodedKeyData == NULL) {
    return NULL;
  }

  CFMutableDataRef pemData = CFDataCreateMutable(kCFAllocatorDefault, 0);
  CFDataAppendBytes(pemData, (const uint8_t *)header, strlen(header));
  CFDataAppendBytes(pemData, CFDataGetBytePtr(encodedKeyData), CFDataGetLength(encodedKeyData));
  CFDataAppendBytes(pemData, (const uint8_t *)footer, strlen(footer));

  CFRelease(encodedKeyData);

  return pemData;
}

/*
    Initialise a SecKeyRef from binary data, supports encoded private and public
    keys.

    This uses SecItemImport to guess what the key format is, a variety are
    supported, see _libssh2_rsa_new_private and _libssh2_dsa_new_private for the
    supported format matrices.

    keyRef     - Out parameter, populated with an owned key on successful
                 return.
    keyData    - Initialised binary key data.
    type       - The private / public type of this key, used as a hint.
    filename   - nul terminated C string. Optional, can be NULL. The location
                 where this key was read from disk. Used as part of the guess
                 heuristic.
    passphrase - nul terminated C string. Optional, can be NULL. If the key is
                 found to be encrypted, this passphrase is used for the key
                 derivation to decrypt the key.

    Returns 0 if the key was successfully parsed, 1 otherwise.
 */
static int _libssh2_key_new_from_data(SecKeyRef *keyRef, CFDataRef keyData, SecExternalItemType type, char const *filename, char const *passphrase) {
  CFURLRef cfLocation = NULL;
  if (filename != NULL) {
    cfLocation = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (UInt8 const *)filename, strlen(filename), false);
  }

  CFStringRef cfPassphrase = NULL;
  if (passphrase != NULL) {
    cfPassphrase = CFStringCreateWithBytes(kCFAllocatorDefault, (UInt8 const *)passphrase, strlen((const char *)passphrase), kCFStringEncodingASCII, false);
  }

  CFArrayRef attributes = CFArrayCreate(kCFAllocatorDefault, (void const **)&kSecAttrIsExtractable, 1, &kCFTypeArrayCallBacks);

  SecExternalFormat format = kSecFormatUnknown;
  SecExternalItemType typeRef = type;
  SecItemImportExportKeyParameters parameters = {
    .version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,
    .passphrase = cfPassphrase,
    .keyAttributes = attributes,
  };
  CFArrayRef items = NULL;

  CFDataRef newKeyData = CFRetain(keyData);

  do {
    if (cfLocation == NULL) {
      break;
    }
    if (cfPassphrase != NULL) {
      break;
    }
    if (type != kSecItemTypePrivateKey) {
      break;
    }

    CFStringRef pathExtension = CFURLCopyPathExtension(cfLocation);
    if (pathExtension == NULL) {
      break;
    }

    // Non-encrypted PKCS#8 keys are not supported by `impExpPkcs8Import`
    //
    // To fake support for it, we have to wrap the binary key in a PEM container
    // and then import it ¬_¬
    //
    // This causes the files to be recognised as BSAFE format ¯\(°_o)/¯
    CFRange p8Range = CFStringFind(pathExtension, CFSTR("p8"), kCFCompareCaseInsensitive);
    CFRelease(pathExtension);

    if (p8Range.location != 0) {
      break;
    }

    CFDataRef pemData = _libssh2_wrap_data_in_pem(keyData, "-----BEGIN PRIVATE KEY-----\n", "\n-----END PRIVATE KEY-----");
    if (pemData == NULL) {
      break;
    }

    CFRelease(newKeyData);
    newKeyData = pemData;

    CFURLRef newLocation = CFURLCreateCopyDeletingPathExtension(kCFAllocatorDefault, cfLocation);
    CFRelease(cfLocation);
    cfLocation = CFURLCreateCopyAppendingPathExtension(kCFAllocatorDefault, newLocation, CFSTR("pem"));
    CFRelease(newLocation);
  } while (0);

  CFStringRef cfPath = (cfLocation ? CFURLGetString(cfLocation) : NULL);

  OSStatus error = SecItemImport(newKeyData, cfPath, &format, &typeRef, 0, &parameters, NULL, &items);

  CFRelease(newKeyData);
  CFRelease(attributes);

  if (cfLocation != NULL) {
    CFRelease(cfLocation);
  }

  if (cfPassphrase != NULL) {
    CFRelease(cfPassphrase);
  }

  if (error != errSecSuccess) {
    return 1;
  }

  if (CFArrayGetCount(items) > 1) {
    CFRelease(items);
    return 1;
  }

  CFTypeRef item = CFArrayGetValueAtIndex(items, 0);
  if (CFGetTypeID(item) != SecKeyGetTypeID()) {
    CFRelease(items);
    return 1;
  }

  *keyRef = (SecKeyRef)CFRetain(item);

  CFRelease(items);

  return 0;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

/*
    Given a private key, unwrap it to create a process local raw key in the
    given format.

    privateKey    - The key to unwrap and expose the fields of locally.
    privateFormat - The binary format requested for the unwrapped key. See
                    Supported_CSP_Algorithms.doc for the CSSM supported formats
                    for each key type.
    convert       - Block invoked if the key is successfully unwrapped and
                    decoded into the requested format. Not invoked otherwise.
                    The key memory is only valid for the invocation of this
                    block afterwhich it is reclaimed.

    Returns nothing.
 */
static void convert_private_key_to_raw_key(SecKeyRef privateKey, CSSM_KEYBLOB_FORMAT privateFormat, void (^convert)(CSSM_KEY const *)) {
  CSSM_KEY const *keyRef;
  OSStatus error = SecKeyGetCSSMKey(privateKey, &keyRef);
  if (error != errSecSuccess) {
    return;
  }

  if (keyRef->KeyHeader.BlobType == CSSM_KEYBLOB_RAW) {
    convert(keyRef);
    return;
  }

  if (keyRef->KeyHeader.BlobType != CSSM_KEYBLOB_REFERENCE) {
    return;
  }

  CSSM_CSP_HANDLE csp;
  error = SecKeyGetCSPHandle(privateKey, &csp);
  if (error != errSecSuccess) {
    return;
  }

  CSSM_KEY rawKey = {};
  CSSM_ACCESS_CREDENTIALS credentials = {};

  CSSM_CC_HANDLE context;
  CSSM_RETURN cssmError = CSSM_CSP_CreateSymmetricContext(csp, CSSM_ALGID_NONE, CSSM_ALGMODE_NONE, &credentials, NULL, NULL, CSSM_PADDING_NONE, 0, &context);
  if (cssmError != CSSM_OK) {
    return;
  }

  CSSM_CONTEXT_ATTRIBUTE wrapFormat = {
    .AttributeType = CSSM_ATTRIBUTE_PRIVATE_KEY_FORMAT,
    .AttributeLength = sizeof(uint32),
    .Attribute.Uint32 = privateFormat,
  };
  cssmError = CSSM_UpdateContextAttributes(context, 1, &wrapFormat);
  if (cssmError != CSSM_OK) {
    CSSM_DeleteContext(context);
    return;
  }

  cssmError = CSSM_WrapKey(context, &credentials, keyRef, NULL, &rawKey);
  if (cssmError != CSSM_OK) {
    CSSM_DeleteContext(context);
    return;
  }

  convert(&rawKey);

  CSSM_DeleteContext(context);
}

/*
    Encode the given blob conforming to the given format with the given template
    and initialise a key with the result.

    keyRef    - Out parameter, populated with an owned key on successful return.
    keyClass  - The class, private or public, of the encoded bytes.
    bytes     - A pointer to the structured data compatible with templates.
    templates - An ASN.1 schema to encode bytes with.

    Returns 0 if the key was initialised successfully, 1 otherwise.
 */
static int _libssh2_new_from_binary_template(SecKeyRef *keyRef,
                                             CSSM_KEYCLASS keyClass,
                                             void const *bytes,
                                             SecAsn1Template const *templates) {
  SecExternalItemType type;
  switch (keyClass) {
    case CSSM_KEYCLASS_PRIVATE_KEY:
      type = kSecItemTypePrivateKey;
      break;
    case CSSM_KEYCLASS_PUBLIC_KEY:
      type = kSecItemTypePublicKey;
      break;
    default:
      return 1;
  }

  SecAsn1CoderRef coder = NULL;
  OSStatus error = SecAsn1CoderCreate(&coder);
  if (error != noErr) {
    return 1;
  }

  CSSM_DATA keyData;
  error = SecAsn1EncodeItem(coder, bytes, templates, &keyData);
  if (error != noErr) {
    SecAsn1CoderRelease(coder);
    return 1;
  }

  CFDataRef cfKeyData = CreateDataFromAsn1Item(&keyData);

  SecAsn1CoderRelease(coder);

  int keyError = _libssh2_key_new_from_data(keyRef, cfKeyData, type, NULL, NULL);

  CFRelease(cfKeyData);

  return keyError;
}

#pragma clang diagnostic pop

/*
    Initialise a SecKeyRef from a file path, supports encoded private and public
    keys.

    filename - This file is read to get the key data.

    See _libssh2_key_new_from_data for documentation on the parameters.

    Returns 0 if the key was successfully decoded, 1 otherwise.
 */
static int _libssh2_key_new_from_path(SecKeyRef *keyRef, SecExternalItemType type, char const *filename, char const *passphrase) {
  assert(keyRef != NULL);
  assert(filename != NULL);

  CFDataRef keyData = CreateDataFromFile(filename);
  if (keyData == NULL) {
    return 1;
  }

  int error = _libssh2_key_new_from_data(keyRef, keyData, type, filename, passphrase);

  CFRelease(keyData);

  return error;
}

#pragma mark - PKCS#1 RSA

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

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
} _libssh2_pkcs1_rsa_private_key;

typedef enum {
  RSA_Version_TwoPrime = 0,
  RSA_Version_Multi = 1,
} RSA_Version;

static SecAsn1Template const _libssh2_pkcs1_rsa_private_key_template[] = {
  { .kind = SEC_ASN1_SEQUENCE, .size = sizeof(_libssh2_pkcs1_rsa_private_key) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, version) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, modulus) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, publicExponent) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, privateExponent) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, prime1) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, prime2) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, exponent1) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, exponent2) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, coefficient) },
  { },
};

typedef struct {
  CSSM_DATA modulus;
  CSSM_DATA publicExponent;
} _libssh2_pkcs1_rsa_public_key;

static SecAsn1Template const _libssh2_pkcs1_rsa_public_key_template[] = {
  { .kind = SEC_ASN1_SEQUENCE, .size = sizeof(_libssh2_pkcs1_rsa_public_key) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_public_key, modulus) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_public_key, publicExponent) },
  { },
};

#pragma clang diagnostic pop

#pragma mark - RSA

/*
    Release the given key.

    Returns 0.
 */
int _libssh2_rsa_free(libssh2_rsa_ctx *rsa) {
  CFRelease(rsa);
  return 0;
}

/*
    Create an RSA key from the raw numeric components.

    Can be invoked with only edata and ndata components to create a public key,
    otherwise all components must be given to create a private key.

    rsa                          - Out parameter, populated with an owned key on
                                   successful return.
    e, n, d, p, q, e1, e2, coeff - Positive integer in big-endian form.

    Returns 0 if the key was created, 1 otherwise.
*/
int _libssh2_rsa_new(libssh2_rsa_ctx **rsa,
                     const unsigned char *edata,
                     unsigned long elen,
                     const unsigned char *ndata,
                     unsigned long nlen,
                     const unsigned char *ddata,
                     unsigned long dlen,
                     const unsigned char *pdata,
                     unsigned long plen,
                     const unsigned char *qdata,
                     unsigned long qlen,
                     const unsigned char *e1data,
                     unsigned long e1len,
                     const unsigned char *e2data,
                     unsigned long e2len,
                     const unsigned char *coeffdata,
                     unsigned long coefflen) {
  assert(rsa != NULL);

  assert(edata != NULL);
  assert(ndata != NULL);

  if (ddata != NULL) {
    assert(ddata != NULL);
    assert(pdata != NULL);
    assert(qdata != NULL);
    assert(e1data != NULL);
    assert(e2data != NULL);
    assert(e2data != NULL);
    assert(coeffdata != NULL);

    uint8_t version = RSA_Version_TwoPrime;

    _libssh2_pkcs1_rsa_private_key keyData = {
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
    return _libssh2_new_from_binary_template(rsa, CSSM_KEYCLASS_PRIVATE_KEY, &keyData, _libssh2_pkcs1_rsa_private_key_template);
  }

  _libssh2_pkcs1_rsa_public_key keyData = {
    .modulus = {
      .Length = nlen,
      .Data = (uint8_t *)ndata,
    },
    .publicExponent = {
      .Length = elen,
      .Data = (uint8_t *)edata,
    },
  };
  return _libssh2_new_from_binary_template(rsa, CSSM_KEYCLASS_PUBLIC_KEY, &keyData, _libssh2_pkcs1_rsa_public_key_template);
}

/*
    Create an RSA private key from a file.

    Supported formats:

        Format  | Encrypted | Non-encrypted |

    PKCS#1 PEM        x             x
    PKCS#1 DER                      x
    PKCS#8 PEM        x             x
    PKCS#8 DER        x             x

    rsa        - Out parameter, populated with an owned key on successful
                 return.
    session    - Non-NULL when invoked from libssh2.
    filename   - nul terminated C string. Path to the private key file.
    passphrase - nul terminated C string. Optional  may be NULL, not covariant
                 with whether the private key is encrypted.

    Returns 0 if the key is created, 1 otherwise.
*/
int _libssh2_rsa_new_private(libssh2_rsa_ctx **rsa,
                             LIBSSH2_SESSION *session,
                             const char *filename,
                             unsigned const char *passphrase) {
  return _libssh2_key_new_from_path(rsa, kSecItemTypePrivateKey, filename, (char const *)passphrase);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

/*
    Convert the given raw RSA private PKCS#1 CSSM_KEY to a public key.

    keyRef - Non NULL raw CSSM_KEY.

    Returns an initialised owned SecKeyRef or NULL.
 */
static SecKeyRef convert_rsa_private_key(CSSM_KEY const *keyRef) {
  if (keyRef->KeyHeader.AlgorithmId != CSSM_ALGID_RSA) return NULL;
  if (keyRef->KeyHeader.Format != CSSM_KEYBLOB_RAW_FORMAT_PKCS1) return NULL;
  if (keyRef->KeyHeader.KeyClass != CSSM_KEYCLASS_PRIVATE_KEY) return NULL;

  SecAsn1CoderRef coder;
  OSStatus error = SecAsn1CoderCreate(&coder);
  if (error != errSecSuccess) {
    return NULL;
  }

  _libssh2_pkcs1_rsa_private_key privateKeyData;
  error = SecAsn1Decode(coder, keyRef->KeyData.Data, keyRef->KeyData.Length, _libssh2_pkcs1_rsa_private_key_template, &privateKeyData);
  if (error != errSecSuccess) {
    SecAsn1CoderRelease(coder);
    return NULL;
  }

  SecKeyRef publicKey;
  int keyError = _libssh2_rsa_new(&publicKey, privateKeyData.publicExponent.Data, privateKeyData.publicExponent.Length, privateKeyData.modulus.Data, privateKeyData.modulus.Length, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0);

  SecAsn1CoderRelease(coder);

  if (keyError != 0) {
    return NULL;
  }

  return publicKey;
}

/*
    Convert the given key to a public key.

    The given key may already be a public key, in which case the same key is
    returned with a +1 retain count.

    key - A private or public RSA key.

    Returns an initialised owned public RSA SecKeyRef or NULL.
 */
static SecKeyRef convert_rsa_private_key_to_public_key(SecKeyRef key) {
  __block SecKeyRef publicKey;
  convert_private_key_to_raw_key(key, CSSM_KEYBLOB_RAW_FORMAT_PKCS1, ^(CSSM_KEY const *keyRef) {
    if (keyRef->KeyHeader.AlgorithmId == CSSM_ALGID_RSA && keyRef->KeyHeader.KeyClass == CSSM_KEYCLASS_PUBLIC_KEY) {
      publicKey = (SecKeyRef)CFRetain(key);
    }
    else {
      publicKey = convert_rsa_private_key(keyRef);
    }
  });
  return publicKey;
}

#pragma clang diagnostic pop

/*
    Verify an RSA signature with an RSA key.

    The given RSA key can be a private or public key.

    rsa     - Initialised RSA key, non NULL.
    sig     - Binary data, non NULL.
    sig_len - Length of sig, non zero.
    m       - Binary message, non NULL.
    m_len   - Length of m, non zero.

    Returns 0 if the signature is valid, 1 otherwise.
 */
int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                             const unsigned char *sig,
                             unsigned long sig_len,
                             const unsigned char *m,
                             unsigned long m_len) {
  assert(rsa != NULL);
  assert(sig != NULL);
  assert(m != NULL);

  SecKeyRef publicKey = convert_rsa_private_key_to_public_key(rsa);
  if (publicKey == NULL) {
    return 1;
  }

  bool verify = _libssh2_key_verify_hash(publicKey, sig, sig_len, m, m_len);

  CFRelease(publicKey);

  return verify ? 0 : 1;
}

/*
    Sign a SHA1 hash with an RSA key private key.

    session       - In, non NULL when invoked from libssh2.
    rsa           - Initialised RSA private key, non NULL.
    hash          - In parameter, SHA1 hash bytes.
    hash_len      - In parameter, length of hash.
    signature     - Out parameter, populated with a malloced buffer on
                    successful return.
    signature_len - Out parameter, populated with the length of the malloced
                    signature on successful return.

    Returns 0 if the signature has been signed, 1 otherwise.
 */
int _libssh2_rsa_sha1_sign(LIBSSH2_SESSION *session,
                           libssh2_rsa_ctx *rsa,
                           const unsigned char *hash,
                           size_t hash_len,
                           unsigned char **signature,
                           size_t *signature_len) {
  bool sign = _libssh2_key_sign_hash(session, rsa, hash, hash_len, signature, signature_len);
  return sign ? 0 : 1;
}

#pragma mark - OpenSSL DSA

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

typedef struct {
  CSSM_DATA p;
  CSSM_DATA q;
  CSSM_DATA g;
} _libssh2_dsa_params;

typedef struct {
  CSSM_DATA	version;
  _libssh2_dsa_params params;
  CSSM_DATA	pub;
  CSSM_DATA	priv;
} _libssh2_openssl_dsa_private_key;

static SecAsn1Template const _libssh2_openssl_dsa_private_key_template[] = {
  { .kind = SEC_ASN1_SEQUENCE, .size = sizeof(_libssh2_openssl_dsa_private_key) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_openssl_dsa_private_key, version) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_openssl_dsa_private_key, params) + offsetof(_libssh2_dsa_params, p) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_openssl_dsa_private_key, params) + offsetof(_libssh2_dsa_params, q) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_openssl_dsa_private_key, params) + offsetof(_libssh2_dsa_params, g) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_openssl_dsa_private_key, pub) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_openssl_dsa_private_key, priv) },
  { },
};

typedef struct {
  SecAsn1Oid oid;
  _libssh2_dsa_params params;
} _libssh2_dsa_alg;

typedef struct {
  _libssh2_dsa_alg alg;
  CSSM_DATA pub;
} _libssh2_openssl_dsa_public_key;

static SecAsn1Template _libssh2_dsa_params_template[] = {
  { .kind = SEC_ASN1_SEQUENCE, .size = sizeof(_libssh2_dsa_params) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_dsa_params, p) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_dsa_params, q) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_dsa_params, g) },
  { },
};

static SecAsn1Template const _libssh2_dsa_alg_template[] = {
  { .kind = SEC_ASN1_SEQUENCE, .size = sizeof(_libssh2_dsa_alg) },
  { .kind = SEC_ASN1_OBJECT_ID, .offset = offsetof(_libssh2_dsa_alg, oid) },
  { .kind = SEC_ASN1_INLINE, .offset = offsetof(_libssh2_dsa_alg, params), .sub = _libssh2_dsa_params_template },
  { },
};

static SecAsn1Template const _libssh2_openssl_dsa_public_key_template[] = {
  { .kind = SEC_ASN1_SEQUENCE, .size = sizeof(_libssh2_openssl_dsa_public_key) },
  { .kind = SEC_ASN1_INLINE, .offset = offsetof(_libssh2_openssl_dsa_public_key, alg), .sub = _libssh2_dsa_alg_template },
  { .kind = SEC_ASN1_BIT_STRING, .offset = offsetof(_libssh2_openssl_dsa_public_key, pub), },
  { },
};

typedef struct {
  CSSM_DATA r;
  CSSM_DATA s;
} _libssh2_dsa_signature;

static SecAsn1Template const _libssh2_dsa_signature_template[] = {
  { .kind = SEC_ASN1_SEQUENCE, .size = sizeof(_libssh2_dsa_signature) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_dsa_signature, r) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_dsa_signature, s) },
  { },
};

#pragma clang diagnostic pop

#pragma mark - DSA

/*
    Release the given key.

    Returns 0.
 */
int _libssh2_dsa_free(libssh2_dsa_ctx *dsa) {
  CFRelease(dsa);
  return 0;
}

/*
    Create a DSA key from the raw numeric components.

    Can be invoked without x to create a public key.

    dsa           - Out parameter, populated with an owned key on successful
                    return.
    p, q, g, y, x - Positive integer in big-endian form.

    Returns 0 if the key is created, 1 otherwise.
 */
int _libssh2_dsa_new(libssh2_dsa_ctx **dsa,
                     const unsigned char *pdata,
                     unsigned long plen,
                     const unsigned char *qdata,
                     unsigned long qlen,
                     const unsigned char *gdata,
                     unsigned long glen,
                     const unsigned char *ydata,
                     unsigned long ylen,
                     const unsigned char *x,
                     unsigned long xlen) {
  assert(dsa != NULL);
  assert(pdata != NULL);
  assert(qdata != NULL);
  assert(gdata != NULL);
  assert(ydata != NULL);

  _libssh2_dsa_params params = {
    .p = {
      .Data = (uint8_t *)pdata,
      .Length = plen,
    },
    .q = {
      .Data = (uint8_t *)qdata,
      .Length = qlen,
    },
    .g = {
      .Data = (uint8_t *)gdata,
      .Length = glen,
    },
  };

  if (x != NULL) {
    uint8_t version = 1;

    _libssh2_openssl_dsa_private_key keyData = {
      .version = {
        .Data = &version,
        .Length = sizeof(version),
      },
      .params = params,
      .pub = {
        .Data = (uint8_t *)ydata,
        .Length = ylen,
      },
      .priv = {
        .Data = (uint8_t *)x,
        .Length = xlen,
      },
    };
    return _libssh2_new_from_binary_template(dsa, CSSM_KEYCLASS_PRIVATE_KEY, &keyData, _libssh2_openssl_dsa_private_key_template);
  }

  _libssh2_openssl_dsa_public_key publicKeyData = {
    .alg = {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
      .oid = CSSMOID_DSA_CMS,
#pragma clang diagnostic pop
      .params = params,
    },
  };

  SecAsn1CoderRef coder;
  OSStatus error = SecAsn1CoderCreate(&coder);
  if (error != errSecSuccess) {
    return 1;
  }

  SecAsn1Item pub = {
    .Data = (uint8_t *)ydata,
    .Length = ylen,
  };
  error = SecAsn1EncodeItem(coder, &pub, kSecAsn1UnsignedIntegerTemplate, &publicKeyData.pub);
  if (error != errSecSuccess) {
    SecAsn1CoderRelease(coder);
    return 1;
  }

  publicKeyData.pub.Length *= 8;

  int keyError = _libssh2_new_from_binary_template(dsa, CSSM_KEYCLASS_PUBLIC_KEY, &publicKeyData, _libssh2_openssl_dsa_public_key_template);

  SecAsn1CoderRelease(coder);

  return keyError;
}

/*
    Create a DSA private key from a file.

    Supported formats:

    Format      | Encrypted | Non-encrypted |

    PKCS#1 PEM        x             x
    PKCS#1 DER                      x
    PKCS#8 PEM        x
    PKCS#8 DER        x

    dsa        - Out parameter, populated with an owned key on successful
                 return.
    session    - In parameter, non NULL when invoked from libssh2.
    filename   - nul terminated C string. Path to the private key file.
    passphrase - nul terminated C string. Optional, may be NULL, not covariant
                 with whether the private key is encrypted.

    Returns 0 if the key is created, 1 otherwise.
 */
int _libssh2_dsa_new_private(libssh2_dsa_ctx **dsa,
                             LIBSSH2_SESSION *session,
                             const char *filename,
                             unsigned const char *passphrase) {
  return _libssh2_key_new_from_path(dsa, kSecItemTypePrivateKey, filename, (char const *)passphrase);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

/*
    Convert the given raw DSA private OpenSSL CSSM_KEY to a public key.

    keyRef - Non NULL raw CSSM_KEY.

    Returns an initialised owned SecKeyRef or NULL.
 */
static SecKeyRef convert_dsa_private_key(CSSM_KEY const *keyRef) {
  if (keyRef->KeyHeader.AlgorithmId != CSSM_ALGID_DSA) return NULL;
  if (keyRef->KeyHeader.Format != CSSM_KEYBLOB_RAW_FORMAT_OPENSSL) return NULL;
  if (keyRef->KeyHeader.KeyClass != CSSM_KEYCLASS_PRIVATE_KEY) return NULL;

  SecAsn1CoderRef coder;
  OSStatus error = SecAsn1CoderCreate(&coder);
  if (error != errSecSuccess) {
    return NULL;
  }

  _libssh2_openssl_dsa_private_key privateKeyData;
  error = SecAsn1Decode(coder, keyRef->KeyData.Data, keyRef->KeyData.Length, _libssh2_openssl_dsa_private_key_template, &privateKeyData);
  if (error != errSecSuccess) {
    SecAsn1CoderRelease(coder);
    return NULL;
  }

  SecKeyRef publicKey;
  int keyError = _libssh2_dsa_new(&publicKey, privateKeyData.params.p.Data, privateKeyData.params.p.Length, privateKeyData.params.q.Data, privateKeyData.params.q.Length, privateKeyData.params.g.Data, privateKeyData.params.g.Length, privateKeyData.pub.Data, privateKeyData.pub.Length, NULL, 0);

  SecAsn1CoderRelease(coder);

  if (keyError != 0) {
    return NULL;
  }

  return publicKey;
}

/*
    Convert the given key to a public key.

    The given key may already be a public key, in which case the same key is
    returned with a +1 retain count.

    key - A private or public DSA key.

    Returns an initialised owned public DSA SecKeyRef or NULL.
 */
static SecKeyRef convert_dsa_private_key_to_public_key(SecKeyRef key) {
  __block SecKeyRef publicKey;
  convert_private_key_to_raw_key(key, CSSM_KEYBLOB_RAW_FORMAT_OPENSSL, ^(CSSM_KEY const *keyRef) {
    if (keyRef->KeyHeader.AlgorithmId == CSSM_ALGID_DSA && keyRef->KeyHeader.KeyClass == CSSM_KEYCLASS_PUBLIC_KEY) {
      publicKey = (SecKeyRef)CFRetain(key);
    }
    else {
      publicKey = convert_dsa_private_key(keyRef);
    }
  });
  return publicKey;
}

#pragma clang diagnostic pop

/*
    Verify a DSA signature with a DSA key.

    The given DSA key can be a private or public DSA key.

    dsa     - Initialised DSA key, non NULL.
    sig     - Binary data, non NULL. Two 160 bit / 20 byte integers.
    m       - Binary message, non NULL.
    m_len   - Length of m, non zero.

    Returns 0 if the signature is valid, 1 otherwise.
 */
int _libssh2_dsa_sha1_verify(libssh2_dsa_ctx *dsa,
                             const unsigned char sig[40],
                             const unsigned char *m,
                             unsigned long m_len) {
  assert(dsa != NULL);
  assert(sig != NULL);
  assert(m != NULL);

  SecKeyRef publicKey = convert_dsa_private_key_to_public_key(dsa);
  if (publicKey == NULL) {
    return 1;
  }

  /*
      Transform the two 160 bit integers back into an ASN.1 structure
   */

  SecAsn1CoderRef coder = NULL;
  OSStatus error = SecAsn1CoderCreate(&coder);
  if (error != noErr) {
    CFRelease(publicKey);
    return 1;
  }

  _libssh2_dsa_signature dsaSignature = {
    .r = {
      .Data = (uint8_t *)sig,
      .Length = 20,
    },
    .s = {
      .Data = (uint8_t *)sig + 20,
      .Length = 20,
    },
  };

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  CSSM_DATA encodedSignature;
#pragma clang diagnostic pop
  error = SecAsn1EncodeItem(coder, &dsaSignature, _libssh2_dsa_signature_template, &encodedSignature);
  if (error != noErr) {
    SecAsn1CoderRelease(coder);
    CFRelease(publicKey);
    return 1;
  }

  bool verify = _libssh2_key_verify_hash(publicKey, encodedSignature.Data, encodedSignature.Length, m, m_len);

  SecAsn1CoderRelease(coder);
  CFRelease(publicKey);

  return verify ? 0 : 1;
}

/*
    Sign a SHA1 hash with a DSA private key.

    dsa       - Initialised DSA private key, non NULL.
    hash      - In parameter, SHA1 hash bytes.
    hash_len  - In parameter, length of hash.
    signature - In parameter, pre malloced buffer of 40 zeroed bytes.

    Returns 0 if the signature has been signed, 1 otherwise.
 */
int _libssh2_dsa_sha1_sign(libssh2_dsa_ctx *dsa,
                           const unsigned char *hash,
                           unsigned long hash_len,
                           unsigned char sig_out[40]) {
  unsigned char *sig;
  size_t sig_len;
  bool sign = _libssh2_key_sign_hash(NULL, dsa, hash, hash_len, &sig, &sig_len);
  if (!sign) {
    return 1;
  }

  /*
      DSA key signatures are encoded in the following ASN.1 schema before being
      returned by the sign transformation.

      Dss-Sig-Value  ::=  SEQUENCE  {
        r       INTEGER,
        s       INTEGER  }

      libssh2 expects the raw two 160 bit / 20 byte integers, decode and pack
      them.
   */

  SecAsn1CoderRef coder = NULL;
  OSStatus error = SecAsn1CoderCreate(&coder);
  if (error != noErr) {
    free(sig);
    return 1;
  }

  _libssh2_dsa_signature dsa_signature;
  error = SecAsn1Decode(coder, sig, sig_len, _libssh2_dsa_signature_template, &dsa_signature);
  if (error != noErr || (dsa_signature.r.Length != 20 || dsa_signature.s.Length != 20)) {
    SecAsn1CoderRelease(coder);
    free(sig);
    return 1;
  }

  memcpy(sig_out, dsa_signature.r.Data, 20);
  memcpy(sig_out + 20, dsa_signature.s.Data, 20);

  SecAsn1CoderRelease(coder);
  free(sig);

  return 0;
}

#pragma mark - Ciphers

/*
    Initialise a cipher.

    ctx     - Out, non-NULL, will be populated with a cipher on successful
              return.
    algo    - Cipher algorithm, specifies the type, key size and mode.
    iv      - In parameter, The initialisation vector, is the length of the
              selected cipher blocksize.
    secret  - In parameter. The secret key, is the length of the selected cipher
              key size.
    encrypt - 1 if encryption is requested, 0 if decryption is requested.

    Returns 0 if the cipher is successfully initialised, 1 otherwise.
 */
int _libssh2_cipher_init(_libssh2_cipher_ctx *ctx,
                         _libssh2_cipher_type(algo),
                         unsigned char *iv,
                         unsigned char *secret,
                         int encrypt) {
  assert(ctx != NULL);
  assert(iv != NULL);
  assert(secret != NULL);

  CCAlgorithm alg;
  CCMode mode = kCCModeCBC;
  switch (algo) {
    case _libssh2_cipher_aes256:
    case _libssh2_cipher_aes192:
    case _libssh2_cipher_aes128:
      alg = kCCAlgorithmAES;
      break;
    case _libssh2_cipher_aes256ctr:
    case _libssh2_cipher_aes192ctr:
    case _libssh2_cipher_aes128ctr:
      alg = kCCAlgorithmAES;
      mode = kCCModeCTR;
      break;
    case _libssh2_cipher_blowfish:
      alg = kCCAlgorithmBlowfish;
      break;
    case _libssh2_cipher_arcfour:
      alg = kCCAlgorithmRC4;
      break;
    case _libssh2_cipher_cast5:
      alg = kCCAlgorithmCAST;
      break;
    case _libssh2_cipher_3des:
      alg = kCCAlgorithm3DES;
      break;
  }

  size_t keyLength;
  switch (algo) {
    case _libssh2_cipher_aes256:
    case _libssh2_cipher_aes256ctr:
      keyLength = 32;
      break;
    case _libssh2_cipher_aes192:
    case _libssh2_cipher_aes192ctr:
      keyLength = 24;
      break;
    case _libssh2_cipher_aes128:
    case _libssh2_cipher_aes128ctr:
      keyLength = 16;
      break;
    case _libssh2_cipher_blowfish:
      keyLength = 16;
      break;
    case _libssh2_cipher_arcfour:
      keyLength = 16;
      break;
    case _libssh2_cipher_cast5:
      keyLength = 16;
      break;
    case _libssh2_cipher_3des:
      keyLength = 24;
      break;
  }

  CCCryptorStatus error = CCCryptorCreateWithMode(encrypt == 1 ? kCCEncrypt : kCCDecrypt, mode, alg, ccNoPadding, iv, secret, keyLength, NULL, 0, 0, 0, ctx);
  if (error != kCCSuccess) {
    return 1;
  }

  return 0;
}

/*
    Execute the cipher against the given data block.

    ctx       - In parameter. An initialised cipher.
    algo      - Cipher algorithm, specifies the type, key size and mode.
    encrypt   - 1 if encryption is requested, 0 if decryption is requested.
    block     - In/out parameter. The data to encrypt/decrypt. The
                decrypted/encrypted data is written back to this buffer on
                successful return.
    blocksize - The length of block in bytes.

    Returns 0 if the block is successfuly encrypted/decrypted, 1 otherwise.
 */
int _libssh2_cipher_crypt(_libssh2_cipher_ctx *ctx,
                          _libssh2_cipher_type(algo),
                          int encrypt,
                          unsigned char *block,
                          size_t blocksize) {
  assert(ctx != NULL);
  assert(block != NULL);

  size_t dataOut;
  // inline encrypt/decrypt
  CCCryptorStatus error = CCCryptorUpdate(*ctx, block, blocksize, block, blocksize, &dataOut);
  if (error != kCCSuccess) {
    return 1;
  }

  return 0;
}

/*
    Release the given cipher.

    Returns nothing.
 */
void _libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx) {
  CCCryptorRelease(*ctx);
}

/*
    Initialise AES CTR (counter) mode.

    Unimplemented.
 */
void _libssh2_init_aes_ctr(void) {

}

#pragma mark - Private Public Keys

/*
    Extract a public key from a private key file.

    Used to provide the public key authentication method, only RSA and DSA keys
    are supported.

    If the server accepts the returned public key, the client will be asked to
    sign something with the corresponding private key to prove ownership.

    session            - In parameter. May be NULL when testing, when non-NULL
                         should be used for allocations.
    method_ref         - Out parameter, one of "ssh-rsa" and "ssh-dss" based on
                         the public key type. Populated with a malloced buffer
                         the caller must free on successful return.
    method_len_ref     - Out parameter, the length of the method string written
                         on successful return.
    pubkeydata_ref     - Out parameter, See `gen_publickey_from_rsa` and
                         `gen_publickey_from_dsa` from the openssl
                         implementation for a comparison of the expected.
                         Populated with a malloced buffer the caller must free
                         on successful return.
    pubkeydata_len_ref - Out parameter, the length of the pubkeydata data
                         written on successful return.
    privatekey         - nul terminated C string. File system path to the
                         private key file, non NULL.
    passphrase         - nul terminated C String. Optional, may be NULL. The
                         passphrase for the private key file. Not covariant with
                         whether the private key is encrypted.

    Returns 0 if the public key is created, 1 otherwise.
 */
int _libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                              unsigned char **method_ref,
                              size_t *method_len_ref,
                              unsigned char **pubkeydata_ref,
                              size_t *pubkeydata_len_ref,
                              const char *privatekeyPath,
                              const char *passphrase) {
  assert(method_ref != NULL);
  assert(method_len_ref != NULL);
  assert(pubkeydata_ref != NULL);
  assert(pubkeydata_len_ref != NULL);
  assert(privatekeyPath != NULL);

  SecKeyRef key;
  int error = _libssh2_key_new_from_path(&key, kSecItemTypePrivateKey, privatekeyPath, passphrase);
  if (error != 0) {
    return error;
  }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  CSSM_KEY const *cssmKey;
  OSStatus secErr = SecKeyGetCSSMKey(key, &cssmKey);
#pragma clang diagnostic pop
  if (secErr != errSecSuccess) {
    CFRelease(key);
    return 1;
  }

  void (^appendBigEndianInteger)(CFMutableDataRef, CFDataRef) = ^(CFMutableDataRef pubData, CFDataRef data) {
    uint32_t length = (uint32_t)CFDataGetLength(data);

    bool prependZero = ((*CFDataGetBytePtr(data) & 0x80) == 0x80);
    if (prependZero) {
      length++;
    }

    uint32_t encodedLength = htonl(length);
    CFDataAppendBytes(pubData, (uint8_t *)&encodedLength, 4);

    if (prependZero) {
      uint8_t zero = 0;
      CFDataAppendBytes(pubData, &zero, 1);
    }
    CFDataAppendBytes(pubData, CFDataGetBytePtr(data), CFDataGetLength(data));
  };

  CSSM_ALGORITHMS algorithm = cssmKey->KeyHeader.AlgorithmId;
  if (algorithm == CSSM_ALGID_RSA) {
    __block CFDataRef e = NULL, n = NULL;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    convert_private_key_to_raw_key(key, CSSM_KEYBLOB_RAW_FORMAT_PKCS1, ^(CSSM_KEY const *keyRef) {
#pragma clang diagnostic pop
      SecAsn1CoderRef coder;
      OSStatus error = SecAsn1CoderCreate(&coder);
      if (error != errSecSuccess) {
        return;
      }

      _libssh2_pkcs1_rsa_private_key privateKeyData;
      error = SecAsn1Decode(coder, keyRef->KeyData.Data, keyRef->KeyData.Length, _libssh2_pkcs1_rsa_private_key_template, &privateKeyData);
      if (error != errSecSuccess) {
        SecAsn1CoderRelease(coder);
        return;
      }

      e = CreateDataFromAsn1Item(&privateKeyData.publicExponent);
      n = CreateDataFromAsn1Item(&privateKeyData.modulus);

      SecAsn1CoderRelease(coder);
    });

    if (e == NULL || n == NULL) {
      if (e != NULL) CFRelease(e);
      if (n != NULL) CFRelease(n);
      CFRelease(key);
      return 1;
    }

    char const *method = "ssh-rsa";
    size_t methodLength = strlen(method);

    *method_ref = session ? LIBSSH2_ALLOC(session, methodLength) : malloc(methodLength);
    *method_len_ref = methodLength;
    memcpy(*method_ref, method, methodLength);

    /*
      	method length (4 bytes, network byte order)
     		method (x bytes)
     		e length (4 bytes, network byte order)
     		e (x bytes, var len int encoding, public exponent)
     		n length (4 bytes, network byte order)
     		n (x bytes, var len int encoding, modulus)
     */

    CFMutableDataRef pubData = CFDataCreateMutable(kCFAllocatorDefault, 0);

    uint32_t encodedMethodLength = htonl(methodLength);
    CFDataAppendBytes(pubData, (uint8_t *)&encodedMethodLength, 4);
    CFDataAppendBytes(pubData, (uint8_t *)method, methodLength);

    appendBigEndianInteger(pubData, e);
    appendBigEndianInteger(pubData, n);

    *pubkeydata_len_ref = CFDataGetLength(pubData);
    *pubkeydata_ref = session ? LIBSSH2_ALLOC(session, *pubkeydata_len_ref) : malloc(*pubkeydata_len_ref);
    CFDataGetBytes(pubData, CFRangeMake(0, *pubkeydata_len_ref), *pubkeydata_ref);

    CFRelease(pubData);

    CFRelease(e);
    CFRelease(n);

    CFRelease(key);

    return 0;
  }

  if (algorithm == CSSM_ALGID_DSA) {
    __block CFDataRef p = NULL, q = NULL, g = NULL, pub = NULL;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    convert_private_key_to_raw_key(key, CSSM_KEYBLOB_RAW_FORMAT_OPENSSL, ^(CSSM_KEY const *keyRef) {
#pragma clang diagnostic pop
      SecAsn1CoderRef coder;
      OSStatus error = SecAsn1CoderCreate(&coder);
      if (error != errSecSuccess) {
        return;
      }

      _libssh2_openssl_dsa_private_key privateKeyData;
      error = SecAsn1Decode(coder, keyRef->KeyData.Data, keyRef->KeyData.Length, _libssh2_openssl_dsa_private_key_template, &privateKeyData);
      if (error != errSecSuccess) {
        SecAsn1CoderRelease(coder);
        return;
      }

      p = CreateDataFromAsn1Item(&privateKeyData.params.p);
      q = CreateDataFromAsn1Item(&privateKeyData.params.q);
      g = CreateDataFromAsn1Item(&privateKeyData.params.g);
      pub = CreateDataFromAsn1Item(&privateKeyData.pub);

      SecAsn1CoderRelease(coder);
    });

    if (p == NULL || q == NULL || g == NULL || pub == NULL) {
      if (p != NULL) CFRelease(p);
      if (q != NULL) CFRelease(q);
      if (g != NULL) CFRelease(g);
      if (pub != NULL) CFRelease(pub);
      CFRelease(key);
      return 1;
    }

    char const *method = "ssh-dss";
    size_t methodLength = strlen(method);

    *method_ref = session ? LIBSSH2_ALLOC(session, methodLength) : malloc(methodLength);
    *method_len_ref = methodLength;
    memcpy(*method_ref, method, methodLength);

    /*
        method length (4 bytes, network byte order)
        method (x bytes)
        p length (4 bytes, network byte order)
        p (x bytes)
        q length (4 bytes, network byte order)
        q (x bytes)
        g length (4 bytes, network byte order)
        g (x bytes)
        pub length (4 bytes, network byte order)
        pub (x bytes)
     */

    CFMutableDataRef pubData = CFDataCreateMutable(kCFAllocatorDefault, 0);

    uint32_t encodedMethodLength = htonl(methodLength);
    CFDataAppendBytes(pubData, (uint8_t *)&encodedMethodLength, 4);
    CFDataAppendBytes(pubData, (uint8_t *)method, methodLength);

    appendBigEndianInteger(pubData, p);
    appendBigEndianInteger(pubData, q);
    appendBigEndianInteger(pubData, g);
    appendBigEndianInteger(pubData, pub);

    *pubkeydata_len_ref = CFDataGetLength(pubData);
    *pubkeydata_ref = session ? LIBSSH2_ALLOC(session, *pubkeydata_len_ref) : malloc(*pubkeydata_len_ref);
    CFDataGetBytes(pubData, CFRangeMake(0, *pubkeydata_len_ref), *pubkeydata_ref);

    CFRelease(pubData);

    CFRelease(p);
    CFRelease(q);
    CFRelease(g);
    CFRelease(pub);

    CFRelease(key);

    return 0;
  }

  CFRelease(key);
  return 1;
}
