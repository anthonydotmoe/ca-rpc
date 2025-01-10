#pragma once

#include <string>
#include <compat/dcerpc.h>


class RpcBinding {
public:
    explicit RpcBinding(const std::string& hostname);
    ~RpcBinding();

    // Non-copyable, but movable
    RpcBinding(const RpcBinding&) = delete;
    RpcBinding& operator=(const RpcBinding&) = delete;
    RpcBinding(RpcBinding&& other) noexcept;
    RpcBinding& operator=(RpcBinding&& other) noexcept;

    // Read-only access to the underlying handle
    rpc_binding_handle_t handle() const { return m_handle; }

private:
    rpc_binding_handle_t m_handle = nullptr;

    void initializeBinding(const std::string& hostname);
    void setAuthInfo(const std::string& hostname);
    void freeBinding();
};