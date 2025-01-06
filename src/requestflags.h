#ifndef __REQUESTFLAGS_H__
#define __REQUESTFLAGS_H__

// ExtendedFlags values
#define CERT_REQUEST_FLAG_CT                (1 << 5)
#define CERT_REQUEST_FLAG_PRE_SIGN          (1 << 4)

// Flags values
#define CERT_REQUEST_FLAG_INCLUDE_CRL       (1 << 12)
#define CERT_REQUEST_FLAG_CMC_FULL_PKI      (1 << 13)
#define CERT_REQUEST_FLAG_RENEW_ON_BEHALF   (1 << 9)

// RequestType values
#define REQUEST_TYPE_CA_DETERMINED       (0x00 << 16)  // The client relies on CA to determine the request type.
#define REQUEST_TYPE_PKCS10              (0x01 << 16)  // PKCS #10 request structure.
#define REQUEST_TYPE_NETSCAPE_KEYGEN     (0x02 << 16)  // Netscape KEYGEN request structure.
#define REQUEST_TYPE_CMS                 (0x03 << 16)  // CMS request structure.
#define REQUEST_TYPE_CMC                 (0x04 << 16)  // Certificate Management Messages over CMS (CMC).
#define REQUEST_TYPE_ATTESTATION         (0x05 << 16)  // Response to the attestation CAChallenge.
#define REQUEST_TYPE_SCT_LIST            (0x06 << 16)  // SignedCertificateTimestampList structure.

#endif /* __REQUESTFLAGS_H__ */
