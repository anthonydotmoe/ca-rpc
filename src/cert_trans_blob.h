#pragma once

#include <vector>
#include "ms-icpr.h"

class CertTransBlob {
public:
    CertTransBlob();
    CertTransBlob(const CertTransBlob&) = delete;
    CertTransBlob& operator=(const CertTransBlob&) = delete;
    CertTransBlob(CertTransBlob&& other) noexcept;
    CertTransBlob& operator=(CertTransBlob&& other) noexcept;
    ~CertTransBlob();

    void assign(const std::vector<BYTE>& data);
    void clear();

    ULONG size() const;
    BYTE* data();
    const BYTE* data() const;

    CERTTRANSBLOB get() const;

private:
    ULONG cb;
    BYTE* pb;
};