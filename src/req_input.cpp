#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>

std::vector<unsigned char> validateAndConvertRequest(const std::string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "rb");
    if (!bio) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    // Try to read the file as PEM
    X509_REQ* req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    if (!req) {
        // If PEM reading fails, try DER
        BIO_reset(bio);
        req = d2i_X509_REQ_bio(bio, nullptr);

        if (!req) {
            BIO_free(bio);
            throw std::runtime_error("Invalid certificate request file: " + filename);
        }
    }

    // Convert X509_REQ to DER
    unsigned char *derBuffer = nullptr;
    int derLength = i2d_X509_REQ(req, &derBuffer);
    if (derLength <= 0) {
        X509_REQ_free(req);
        BIO_free(bio);
        throw std::runtime_error("Failed to convert certificate request to DER format");
    }

    // Copy DER data to std::vector
    std::vector<unsigned char> derData(derBuffer, derBuffer + derLength);
    OPENSSL_free(derBuffer);

    // Clean up
    X509_REQ_free(req);
    BIO_free(bio);

    return derData;
}