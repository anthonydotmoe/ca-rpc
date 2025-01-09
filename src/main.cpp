#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include <filesystem>

#include <compat/dcerpc.h>
#include <dce/dcethread.h>

#include <iconv.h>

// Compiled from IDL files
#include "ms-icpr.h"

#include "requestflags.h"
#include "cert_trans_blob.h"
#include "req_input.h"

CertTransBlob loadCsrFile(const std::string& filename);
CertTransBlob prepareTemplateName(const std::string& template_name);
std::string Utf16leToString(const CERTTRANSBLOB& ctbString);
std::string dispositionToString(DWORD dwDisposition);
std::vector<unsigned short> utf8ToUnicode(const std::string& utf8);
void get_ICertPassage_binding(rpc_binding_handle_t* binding_handle, const std::string& hostname);
void chk_dce_err(error_status_t ecode, const std::string& text);
void freeOutParamCERTTRANSBLOB(CERTTRANSBLOB& blob);
void set_auth_info(rpc_binding_handle_t * binding_handle, const std::string& hostname);


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
    throw std::runtime_error("Incorrect usage");
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
    if (server.empty() || ca_name.empty() || template_name.empty() | csr_path.empty()) {
        usage(argv[0]);
    }

    // Prepare to make remote call

    unsigned32 status;
    rpc_binding_handle_t ca_server;
    DWORD outstatus = -1;

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
    get_ICertPassage_binding(&ca_server, server);
    set_auth_info(&ca_server, server);

    // Make the call!
    std::cout << "requesting certificate!" << std::endl;

    DCETHREAD_TRY {
        outstatus = CertServerRequest(ca_server,
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
        printf("ERROR %s(0x%lx): Verify that you have a Kerberos TGT.\n",
            dcethread_exc_getname(thread_exc),
            dcethread_exc_getstatus(thread_exc)
        );
    }
    DCETHREAD_ENDTRY

    std::string disposition, dispositionMessage;
    disposition = dispositionToString(pdwDisposition);
    try {
        dispositionMessage = Utf16leToString(pctbDispositionMessage);
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
        rpc_binding_free(&ca_server, &status);
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
            rpc_binding_free(&ca_server, &status);
            return EXIT_FAILURE;
        }
    }

    // Clean up
    freeOutParamCERTTRANSBLOB(pctbCert);
    freeOutParamCERTTRANSBLOB(pctbEncodedCert);
    freeOutParamCERTTRANSBLOB(pctbDispositionMessage);
    rpc_binding_free(&ca_server, &status);
    return EXIT_SUCCESS;
}

/*
get_ICertPassage_binding()

Gets a binding handle to an RPC interface.

parameters:
    [out]   binding_handle
    [in]    hostname            Internet hostname where server lives

Throws exceptions on DCERPC errors
*/
void get_ICertPassage_binding(
    rpc_binding_handle_t* binding_handle,
    const std::string& hostname
) {
    unsigned_char_p_t string_binding = NULL;
    error_status_t status, free_status;

    // Create a string binding given the parameters and resolve it to a full
    // binding handle using the endpoint mapper. The binding handle resolution
    // is handled by the runtime library.
    rpc_string_binding_compose(
        NULL,
        (unsigned_char_p_t)"ncacn_ip_tcp",
        (unsigned_char_p_t)hostname.c_str(),
        NULL,
        NULL,
        &string_binding,
        &status
    );

    chk_dce_err(status, "rpc_string_binding_compose()");

    rpc_binding_from_string_binding(
        string_binding,
        binding_handle,
        &status
    );

    // Free the binding string first, then check the status of the bind
    rpc_string_free(&string_binding, &free_status);
    chk_dce_err(free_status, "rpc_string_free()");

    chk_dce_err(status, "rpc_binding_from_string_binding()");

    // Resolve the partial binding handle using the endpoint mapper
    rpc_ep_resolve_binding(
        *binding_handle,
        ICertPassage_v0_0_c_ifspec,
        &status
    );
    chk_dce_err(status, "rpc_ep_resolve_binding()");

    return;
}

void chk_dce_err(
    error_status_t ecode,
    const std::string& text
) {
    dce_error_string_t errstr;
    int error_status;
    
    if (ecode != error_status_ok)
    {
        dce_error_inq_text(ecode, errstr, &error_status);
        if (error_status == error_status_ok)
            throw std::runtime_error("ERROR. <" + text + "> error code = 0x" + std::to_string(ecode) + " = <" + std::string(errstr) + ">");
        else
            throw std::runtime_error("ERROR. <" + text + "> error code = 0x" + std::to_string(ecode));
    }
}

std::vector<BYTE> utf8ToUtf16le(const std::string& utf8) {
    // Initialize iconv for UTF-8 to UTF-16LE conversion
    iconv_t conv = iconv_open("UTF-16LE", "UTF-8");
    if (conv == (iconv_t)-1) {
        throw std::runtime_error("iconv_open failed: Cannot initialize converter");
    }

    const char* input = utf8.c_str();
    size_t input_bytes_left = utf8.size() + 1; // Include null terminator
    
    // 2 bytes per UTF-8 character
    size_t output_bytes_left = input_bytes_left * 2;
    std::vector<BYTE> output(output_bytes_left);
    char* output_ptr = reinterpret_cast<char*>(output.data());

    // Perform the conversion
    size_t result = iconv(conv, const_cast<char**>(&input), &input_bytes_left, &output_ptr, &output_bytes_left);
    if (result == (size_t)-1) {
        iconv_close(conv);
        throw std::runtime_error("iconv conversion failed");
    }

    // Calculate the actual size of the converted data
    output.resize(output.size() - output_bytes_left);

    // Clean up iconv
    iconv_close(conv);

    return output;
}

std::vector<unsigned short> utf8ToUnicode(const std::string& utf8) {
    // Initialize iconv for UTF-8 to UTF-16LE conversion
    iconv_t conv = iconv_open("UTF-16LE", "UTF-8");
    if (conv == (iconv_t)-1) {
        throw std::runtime_error("iconv_open failed: Cannot initialize converter");
    }

    const char* input = utf8.c_str();
    size_t input_bytes_left = utf8.size();
    
    // 2 bytes per UTF-8 character + null terminator
    size_t output_bytes_left = (input_bytes_left + 1) * 2;
    std::vector<unsigned short> output(input_bytes_left + 1);
    char* output_ptr = reinterpret_cast<char*>(output.data());

    // Perform the conversion
    size_t result = iconv(conv, const_cast<char**>(&input), &input_bytes_left, &output_ptr, &output_bytes_left);
    if (result == (size_t)-1) {
        iconv_close(conv);
        throw std::runtime_error("iconv conversion failed");
    }

    // Calculate the actual size of the converted data
    //output.resize(output.size() - output_bytes_left);

    // Clean up iconv
    iconv_close(conv);

    return output;
}

std::string Utf16leToString(const CERTTRANSBLOB& ctbString) {
    if (!ctbString.pb || ctbString.cb == 0) {
        return std::string();
    }

    // Initialize iconv
    iconv_t conv = iconv_open("UTF-8", "UTF-16LE");
    if (conv == (iconv_t)-1) {
        throw std::runtime_error("iconv_open failed: Cannot initialize converter");
    }

    // Input buffer: UTF-16LE data
    const char* input = reinterpret_cast<const char*>(ctbString.pb);
    size_t input_bytes_left = ctbString.cb;

    // Estimate output size: UTF-8 is twice the size maybe sometimes hopefully.
    size_t output_bytes_left = input_bytes_left * 2;
    std::vector<char> output_buffer(output_bytes_left);
    char* output_ptr = output_buffer.data();

    // Perform the conversion
    size_t result = iconv(conv, const_cast<char**>(&input), &input_bytes_left, &output_ptr, &output_bytes_left);
    if (result == (size_t)-1) {
        iconv_close(conv);
        throw std::runtime_error("iconv conversion failed");
    }

    // Clean up iconv
    iconv_close(conv);

    return std::string(output_buffer.data(), output_buffer.size() - output_bytes_left);
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

// This function either returns or fails and exits the program.
void set_auth_info(rpc_binding_handle_t *binding_handle, const std::string& hostname) {
    unsigned32 authn_svc = rpc_c_authn_gss_mskrb;
    unsigned32 protect_level = rpc_c_protect_level_pkt_privacy;
    unsigned32 authz_svc = rpc_c_authz_name;
    unsigned32 status;

    std::string princname = "host/" + hostname;

    rpc_binding_set_auth_info(
        *binding_handle,
        (unsigned_char_p_t)princname.c_str(),
        protect_level,
        authn_svc,
        NULL,
        authz_svc,
        &status
    );

    try {
        chk_dce_err(status, "rpc_binding_set_auth_info()");
    }
    catch(const std::exception& e) {
        rpc_binding_free(binding_handle, &status);
        throw std::runtime_error("Unable to set auth info on rpc binding handle. Double check that \"" + princname + "\" is the correct SPN. Exiting.");
    }

    return;
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