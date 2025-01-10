#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include <filesystem>

#include <compat/dcerpc.h>
#include <dce/dcethread.h>

// Compiled from IDL files
#include "ms-icpr.h"

#include "cert_trans_blob.h"
#include "encoding.h"
#include "req_input.h"
#include "requestflags.h"
#include "rpc_client.h"

CertTransBlob loadCsrFile(const std::string& filename);
CertTransBlob prepareTemplateName(const std::string& template_name);
std::string dispositionToString(DWORD dwDisposition);
void freeOutParamCERTTRANSBLOB(CERTTRANSBLOB& blob);

static void usage(const std::string& progname) {
    std::cerr << "usage: " << progname << " -s <server dns name> -c <name of CA> -t <template name> -r <csr path>" << std::endl << std::endl;
    //                     1         2         3         4         5         6         7         8
    //            12345678901234567890123456789012345678901234567890123456789012345678901234567890
    std::cerr << "This utility will request a certificate from a Microsoft Certificate Authority"   << std::endl;
    std::cerr << "using RPC and Kerberos to authenticate. Make sure a TGT is available in the"      << std::endl;
    std::cerr << "credentials cache for the user that this program runs as. A service ticket will"  << std::endl;
    std::cerr << "be retrieved using that TGT.\n"                                                   << std::endl;
    std::cerr << "The output certificate (if issued by the CA) will be placed in the current"       << std::endl;
    std::cerr << "working directory in DER format with the same name as the request file.\n"        << std::endl;
    std::cerr << "Arguments:"                                                                       << std::endl;
    std::cerr << "-s      server dns name:"                                                         << std::endl;
    std::cerr << "        The fully qualified domain name of the server hosting the CA service.\n"  << std::endl;
    std::cerr << "-c      name of CA:"                                                              << std::endl;
    std::cerr << "        Name of the CA service running on the server. Usually the Subject \"CN\"" << std::endl;
    std::cerr << "        listed on the certificate for this CA.\n"                                 << std::endl;
    std::cerr << "-t      templatename:"                                                            << std::endl;
    std::cerr << "        The \"Template name\" of the certificate template to request the"         << std::endl;
    std::cerr << "        certificate under. (Not the \"Template display name\")\n"                 << std::endl;
    std::cerr << "-r      csr path:"                                                                << std::endl;
    std::cerr << "        Path to the certificate request file.\n"                                  << std::endl;
    exit(EXIT_FAILURE);
}

inline std::string prepareOutputName(const std::string& csr_path) {
    return std::string(std::filesystem::path(csr_path).stem().string() + ".cer");
}

int main(int argc, char *argv[]) {
    int opt;
    std::string server, ca_name, template_name, csr_path;

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "s:c:t:r:")) != -1) {
        switch (opt) {
            case 's':
                server = optarg;
                break;
            case 'c':
                ca_name = optarg;
                break;
            case 't':
                template_name = optarg;
                break;
            case 'r':
                csr_path = optarg;
                break;
            default: // '?' case for invalid options
                usage(argv[0]);
        }
    }

    // Check for missing required arguments
    if (server.empty() || ca_name.empty() || template_name.empty() || csr_path.empty()) {
        usage(argv[0]);
    }

    // Prepare to make remote call

    // Inputs
    DWORD dwFlags = REQUEST_TYPE_PKCS10;

    std::vector<unsigned short> caName = utf8ToUnicode(ca_name);
    CertTransBlob attribsBlob = prepareTemplateName(template_name);
    CertTransBlob csrBlob = loadCsrFile(csr_path);
    std::string output_filename = prepareOutputName(csr_path);

    CERTTRANSBLOB pctbAttribs = attribsBlob.get();
    CERTTRANSBLOB pctbRequest = csrBlob.get();
    unsigned short *pwszAuthority = caName.data();

    // Outputs
    DWORD outstatus = -1;
    CERTTRANSBLOB pctbCert;
    CERTTRANSBLOB pctbEncodedCert;
    CERTTRANSBLOB pctbDispositionMessage;
    DWORD pdwRequestId = 0;
    DWORD pdwDisposition = 0;

    // Prepare outputs
    memset(&pctbCert, 0, sizeof(CERTTRANSBLOB));
    memset(&pctbEncodedCert, 0, sizeof(CERTTRANSBLOB));
    memset(&pctbDispositionMessage, 0, sizeof(CERTTRANSBLOB));

    // Create RPC binding
    RpcBinding binding(server);

    // Make the call!
    std::cout << "Requesting certificate!" << std::endl;

    DCETHREAD_TRY {
        outstatus = CertServerRequest(binding.handle(),
            dwFlags,
            pwszAuthority,              // [in]  A null-terminated unicode string that contains the name of the CA.
            &pdwRequestId,              // [out] CA issued request ID
            &pdwDisposition,            // [out] An unsigned integer that identifies the request status for this invocation.
            &pctbAttribs,               // [in]  CERTTRANSBLOB structure that contains a null-terminated unicode string that contains a set of request attributes.
            &pctbRequest,               // [in]  CERTTRANSBLOB structure that contains a certificate request as a raw binary object.
            &pctbCert,                  // [out] CERTTRANSBLOB structure that is empty or contains a simple CMS or a CMC full PKI response for the certificate chain issued by the CA based on the request supplied by the caller.
            &pctbEncodedCert,           // [out] CERTTRANSBLOB structure that is empty or contains the issued certificate. Is an X509 cert encoded by using DER.
            &pctbDispositionMessage     // [out] CERTTRANSBLOB structure that contains a null-terminated unicode string with a message that identifies the status of the request.
        );
    }
    DCETHREAD_CATCH_ALL(thread_exc) {
        std::cerr << "ERROR " << dcethread_exc_getname(thread_exc)
                  << "(0x" << std::hex << dcethread_exc_getstatus(thread_exc)
                  << "): Verify that you have a Kerberos TGT." << std::endl;
    }
    DCETHREAD_ENDTRY

    std::string disposition, dispositionMessage;
    disposition = dispositionToString(pdwDisposition);
    try {
        dispositionMessage = utf16leToString(pctbDispositionMessage);
    } catch (const std::exception& e) {
        dispositionMessage = "(unable to retrieve disposition message)";
    }

    // Failure case
    if (outstatus != 0 || pctbEncodedCert.cb == 0 || pctbEncodedCert.pb == nullptr) {
        std::cerr << "ERROR: CertServerRequest returned 0x" << std::hex << outstatus << std::endl;
        std::cerr << "RequestId: " << std::dec << pdwRequestId << std::endl;
        std::cerr << "dwDisposition: "  << disposition << '(' << std::hex << pdwDisposition << ')' << std::endl;
        std::cerr << "DispositionMessage: \"" << dispositionMessage << '"' << std::endl;
        
        freeOutParamCERTTRANSBLOB(pctbCert);
        freeOutParamCERTTRANSBLOB(pctbEncodedCert);
        freeOutParamCERTTRANSBLOB(pctbDispositionMessage);
        return EXIT_FAILURE;
    }

    // Success case
    else {
        std::cout << "CertServerRequest returned 0x" << std::hex << outstatus << std::endl;
        std::cout << "RequestId: " << std::dec << pdwRequestId << std::endl;
        std::cout << "dwDisposition: "  << disposition << '(' << std::hex << pdwDisposition << ')' << std::endl;
        std::cout << "DispositionMessage: \"" << dispositionMessage << '"' << std::endl;

        try {
            std::ofstream outputfile(output_filename, std::ios::out | std::ios::binary);
            outputfile.write(reinterpret_cast<char*>(pctbEncodedCert.pb), pctbEncodedCert.cb);
            outputfile.close();
        }
        catch (const std::exception& e) {
            std::cerr << "Error writing to output file: " << e.what() << std::endl;
            freeOutParamCERTTRANSBLOB(pctbCert);
            freeOutParamCERTTRANSBLOB(pctbEncodedCert);
            freeOutParamCERTTRANSBLOB(pctbDispositionMessage);
            return EXIT_FAILURE;
        }
    }

    // Clean up
    freeOutParamCERTTRANSBLOB(pctbCert);
    freeOutParamCERTTRANSBLOB(pctbEncodedCert);
    freeOutParamCERTTRANSBLOB(pctbDispositionMessage);
    return EXIT_SUCCESS;
}

CertTransBlob prepareTemplateName(const std::string& template_name) {
    const std::string template_prefix = "CertificateTemplate:";
    std::string combined = template_prefix + template_name;

    // Convert to UTF-16LE
    std::vector<BYTE> utf16_data = utf8ToUtf16le(combined);

    CertTransBlob blob;
    blob.assign(utf16_data);
    return blob;
}

std::string dispositionToString(DWORD dwDisposition) {
    switch (dwDisposition) {
        case 0x0:
            return "CR_DISP_INCOMPLETE";
        case 0x1:
            return "CR_DISP_ERROR";
        case 0x2:
            return "CR_DISP_DENIED";
        case 0x3:
            return "CR_DISP_ISSUED";
        case 0x4:
            return "CR_DISP_ISSUED_OUT_OF_BAND";
        case 0x5:
            return "CR_DISP_UNDER_SUBMISSION";
        case 0x6:
            return "CR_DISP_REVOKE";
        default:
            return "UNKNOWN";
    }
}

// Load a file into a CertTransBlob
CertTransBlob loadCsrFile(const std::string& filename) {
    try {
        // Validate and convert the input file to DER
        std::vector<unsigned char> derData = validateAndConvertRequest(filename);

        // Assign the DER data to a CertTransBlob
        CertTransBlob blob;
        blob.assign(derData);
        return blob;
    } catch (const std::exception& e) {
        throw std::runtime_error("Error loading CSR file: " + std::string(e.what()));
    }
}

void freeOutParamCERTTRANSBLOB(CERTTRANSBLOB& blob) {
    unsigned32 status;
    if (blob.pb) {
        rpc_sm_client_free(blob.pb, &status);
        blob.pb = nullptr;
        blob.cb = 0;
    }
}