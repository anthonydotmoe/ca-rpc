#include "cert_trans_blob.h"
#include <cstring>

CertTransBlob::CertTransBlob() : cb(0), pb(nullptr) {}

CertTransBlob::CertTransBlob(CertTransBlob&& other) noexcept : cb(other.cb), pb(other.pb) {
    other.cb = 0;
    other.pb = nullptr;
}

CertTransBlob& CertTransBlob::operator=(CertTransBlob&& other) noexcept {
    if (this != &other) {
        clear();
        cb = other.cb;
        pb = other.pb;
        other.cb = 0;
        other.pb = nullptr;
    }
    return *this;
}

CertTransBlob::~CertTransBlob() {
    clear();
}

void CertTransBlob::assign(const std::vector<BYTE>& data) {
    clear();
    cb = static_cast<ULONG>(data.size());
    pb = new BYTE[cb];
    std::memcpy(pb, data.data(), cb);
}

void CertTransBlob::clear() {
    if (pb) {
        delete[] pb;
        pb = nullptr;
        cb = 0;
    }
}

ULONG CertTransBlob::size() const {
    return cb;
}

BYTE* CertTransBlob::data() {
    return pb;
}

const BYTE* CertTransBlob::data() const {
    return pb;
}

CERTTRANSBLOB CertTransBlob::get() const {
    CERTTRANSBLOB blob;
    blob.cb = cb;
    blob.pb = pb;
    return blob;
}