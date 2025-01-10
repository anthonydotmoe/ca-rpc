#include "rpc_client.h"

#include <stdexcept>
#include <dce/dcethread.h>
#include "ms-icpr.h"

static void checkDceError(error_status_t ecode, const std::string& context) {
    if (ecode == error_status_ok) {
        return;
    }

    // Convert error code to string
    dce_error_string_t errstr;
    int error_status = 0;
    dce_error_inq_text(ecode, errstr, &error_status);

    if (error_status == error_status_ok) {
        throw std::runtime_error("DCERPC error in [" + context + "]: 0x"
                                 + std::to_string(ecode)
                                 + " ("
                                 + reinterpret_cast<char*>(errstr)
                                 + ")"
        );
    }
    else {
        throw std::runtime_error("DCERPC error in [" + context + "]: 0x"
                                 + std::to_string(ecode)
        );
    }
}

RpcBinding::RpcBinding(const std::string& hostname) {
    try {
        initializeBinding(hostname);
        setAuthInfo(hostname);
    } catch (...) {
        freeBinding();
        throw;
    }
}

RpcBinding::~RpcBinding() {
    freeBinding();
}

void RpcBinding::initializeBinding(const std::string& hostname) {
    // Compose a binding string
    unsigned_char_p_t string_binding = nullptr;
    error_status_t status = error_status_ok;
    error_status_t free_status = error_status_ok;

    rpc_string_binding_compose(
        /* obj_uuid       */ nullptr,
        /* protseq        */ reinterpret_cast<unsigned_char_p_t>(const_cast<char*>("ncacn_ip_tcp")),
        /* network_addr   */ reinterpret_cast<unsigned_char_p_t>(const_cast<char*>(hostname.c_str())),
        /* endpoint       */ nullptr,
        /* options        */ nullptr,
        /* string_binding */ &string_binding,
        /* status         */ &status
    );
    checkDceError(status, "rpc_binding_string_compose()");

    // Convert the string binding to a binding handle
    rpc_binding_from_string_binding(string_binding, &m_handle, &status);

    // Free the binding string first, then check the status of the bind
    rpc_string_free(&string_binding, &free_status);
    checkDceError(free_status, "rpc_string_free()");
    checkDceError(status, "rpc_binding_from_string_binding()");

    // Resolve the binding via the endpoint mapper
    rpc_ep_resolve_binding(m_handle, ICertPassage_v0_0_c_ifspec, &status);
    checkDceError(status, "rpc_ep_resolve_binding()");
}

void RpcBinding::setAuthInfo(const std::string& hostname) {
    // Set authentication info
    unsigned32 authn_svc = rpc_c_authn_gss_mskrb;
    unsigned32 authz_svc = rpc_c_authz_name;
    unsigned32 protect_level = rpc_c_protect_level_pkt_privacy;
    error_status_t status = error_status_ok;
    std::string princname = "host/" + hostname;

    rpc_binding_set_auth_info(
        m_handle,
        reinterpret_cast<unsigned_char_p_t>(const_cast<char*>(princname.c_str())),
        protect_level,
        authn_svc,
        nullptr,    // auth identity
        authz_svc,
        &status
    );
    checkDceError(status, "rpc_binding_set_auth_info()");
}

void RpcBinding::freeBinding() {
    if (m_handle) {
        unsigned32 status = 0;
        rpc_binding_free(&m_handle, &status);
        m_handle = nullptr;
    }
}

RpcBinding::RpcBinding(RpcBinding&& other) noexcept
    : m_handle(other.m_handle)
{
    other.m_handle = nullptr;
}

RpcBinding& RpcBinding::operator=(RpcBinding&& other) noexcept {
    if (this != &other) {
        freeBinding();

        // Move from 'other'
        m_handle = other.m_handle;
        other.m_handle = nullptr;
    }
    return *this;
}