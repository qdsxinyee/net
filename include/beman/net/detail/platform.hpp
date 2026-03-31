// include/beman/net/detail/platform.hpp                              -*-C++-*-
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// ----------------------------------------------------------------------------

#ifndef INCLUDED_INCLUDE_BEMAN_NET_DETAIL_PLATFORM
#define INCLUDED_INCLUDE_BEMAN_NET_DETAIL_PLATFORM

// ----------------------------------------------------------------------------
// This header is the single point of platform abstraction for beman.net.
//
// On POSIX (Linux / macOS) it simply includes the standard system headers.
// On Windows (MSVC) it includes WinSock2 and defines thin compatibility types
// and wrappers so that the rest of the library can be written in POSIX style
// without any #ifdef outside of this file.
//
// Types defined here for Windows:
//   iovec      - matches POSIX iovec (iov_base / iov_len), converts to WSABUF
//   msghdr     - matches POSIX msghdr field names, converts to WSAMSG
//   socklen_t  - int (matches WinSock2 convention)
//   pollfd     - alias for WSAPOLLFD
//   nfds_t     - alias for ULONG
//
// Free functions defined here for Windows:
//   sock_errno()          - WSAGetLastError() / errno
//   close(SOCKET)         - closesocket()
//   fcntl(SOCKET, int, int) - ioctlsocket(FIONBIO) for O_NONBLOCK only
//   poll(...)             - WSAPoll()
//   recvmsg(...)          - WSARecvMsg() (loaded dynamically)
//   sendmsg(...)          - WSASendMsg() (loaded dynamically)
//   getsockopt(...)       - casts void* -> char* for WinSock2
//   setsockopt(...)       - casts const void* -> const char* for WinSock2
// ----------------------------------------------------------------------------

#ifdef _MSC_VER

#define NOMINMAX
#include <WinSock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <cstddef>

// Windows SDK defines `interface` as a macro (expands to `struct`) for COM.
// This conflicts with any identifier named `interface` in C++ code.
#ifdef interface
#undef interface
#endif

// ---- errno compat ----------------------------------------------------------
// On Windows, socket errors come from WSAGetLastError(), not errno.
// sock_errno() abstracts this difference; use it instead of bare errno
// for all socket-related error checks throughout the library.

inline int sock_errno() noexcept { return ::WSAGetLastError(); }

// Map POSIX errno names to their closest Winsock equivalents so that
// switch/case error handling in poll_context compiles unchanged.
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
#ifndef EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif
#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET
#endif
#ifndef EPIPE
#define EPIPE WSAECONNRESET // no direct equivalent
#endif
#ifndef EINTR
#define EINTR WSAEINTR
#endif
#ifndef EAGAIN
#define EAGAIN WSAEWOULDBLOCK
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED WSAECONNREFUSED
#endif

// ---- iovec -----------------------------------------------------------------
// Mirrors POSIX struct iovec exactly (iov_base / iov_len field names).
// Provides an implicit conversion to WSABUF so that WSARecv / WSASend
// call sites can pass iovec* directly after reinterpret_cast.
//
// Note: WSABUF has { ULONG len; CHAR* buf; } - note the reversed order and
// narrower length type. The conversion handles both differences.

struct iovec {
    void*         iov_base;
    ::std::size_t iov_len;

    operator ::WSABUF() const noexcept {
        return ::WSABUF{static_cast<::ULONG>(iov_len), static_cast<::CHAR*>(iov_base)};
    }
};

// ---- msghdr ----------------------------------------------------------------
// Mirrors POSIX struct msghdr field names so that operations.hpp can assign
// msg_iov / msg_iovlen / msg_name / msg_namelen without any #ifdef.
//
// Provides an implicit conversion to WSAMSG for use with WSARecvMsg /
// WSASendMsg.  The Control and dwFlags fields default to zero / empty.

struct msghdr {
    ::SOCKADDR* msg_name    = nullptr;
    ::INT       msg_namelen = 0;
    ::iovec*    msg_iov     = nullptr; // our iovec, not WSABUF
    ::ULONG     msg_iovlen  = 0;
    ::WSABUF    msg_control = {0, nullptr};
    ::DWORD     msg_flags   = 0;

    // Build a WSABUF array from our iovec array on the fly.
    // Called only from recvmsg() / sendmsg() wrappers below.
    // Intentionally not implicit to avoid accidental temporaries holding
    // pointers into a stack-allocated WSABUF array.
    auto to_wsamsg(::WSABUF* bufs, ::ULONG n) noexcept -> ::WSAMSG {
        for (::ULONG i = 0; i < n; ++i)
            bufs[i] = static_cast<::WSABUF>(msg_iov[i]);
        ::WSAMSG w{};
        w.name          = msg_name;
        w.namelen       = msg_namelen;
        w.lpBuffers     = bufs;
        w.dwBufferCount = n;
        w.Control       = msg_control;
        w.dwFlags       = msg_flags;
        return w;
    }
};

// ---- socklen_t -------------------------------------------------------------
using socklen_t = int;

// ---- pollfd / nfds_t -------------------------------------------------------
using pollfd = ::WSAPOLLFD;
using nfds_t = ::ULONG;

inline int poll(::WSAPOLLFD* fds, nfds_t nfds, int timeout) noexcept { return ::WSAPoll(fds, nfds, timeout); }

// ---- close -----------------------------------------------------------------
inline int close(::SOCKET s) noexcept { return ::closesocket(s); }

// ---- fcntl (O_NONBLOCK only) -----------------------------------------------
#ifndef F_SETFL
#define F_SETFL 0
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 1
#endif

inline int fcntl(::SOCKET s, int /*cmd*/, int flags) noexcept {
    ::u_long mode = (flags & O_NONBLOCK) ? 1u : 0u;
    return ::ioctlsocket(s, FIONBIO, &mode);
}

// ---- recvmsg / sendmsg -----------------------------------------------------
// WSARecvMsg and WSASendMsg are Winsock extension functions that must be
// loaded at runtime via WSAIoctl.  We load them once (per process) on the
// first call that provides a valid socket handle.

namespace beman::net::detail::platform {
inline ::LPFN_WSARECVMSG load_wsarecvmsg(::SOCKET s) noexcept {
    static ::LPFN_WSARECVMSG pfn = nullptr;
    if (!pfn) {
        ::GUID  guid = WSAID_WSARECVMSG;
        ::DWORD n    = 0;
        ::WSAIoctl(
            s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &pfn, sizeof(pfn), &n, nullptr, nullptr);
    }
    return pfn;
}
inline ::LPFN_WSASENDMSG load_wsasendmsg(::SOCKET s) noexcept {
    static ::LPFN_WSASENDMSG pfn = nullptr;
    if (!pfn) {
        ::GUID  guid = WSAID_WSASENDMSG;
        ::DWORD n    = 0;
        ::WSAIoctl(
            s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &pfn, sizeof(pfn), &n, nullptr, nullptr);
    }
    return pfn;
}
} // namespace beman::net::detail::platform

// Maximum scatter-gather segments we support in a single recvmsg/sendmsg call.
// Allocated on the stack inside the wrappers to avoid heap allocation.
inline constexpr ::ULONG k_max_iov = 16;

inline int recvmsg(::SOCKET s, msghdr* msg, int /*flags*/) noexcept {
    auto pfn = ::beman::net::detail::platform::load_wsarecvmsg(s);
    if (!pfn) {
        ::WSASetLastError(WSAEOPNOTSUPP);
        return -1;
    }

    ::WSABUF bufs[k_max_iov];
    ::ULONG  n     = (msg->msg_iovlen < k_max_iov) ? msg->msg_iovlen : k_max_iov;
    ::WSAMSG wm    = msg->to_wsamsg(bufs, n);
    ::DWORD  bytes = 0;
    int      rc    = pfn(s, &wm, &bytes, nullptr, nullptr);
    return rc == 0 ? static_cast<int>(bytes) : -1;
}

inline int sendmsg(::SOCKET s, msghdr* msg, int /*flags*/) noexcept {
    auto pfn = ::beman::net::detail::platform::load_wsasendmsg(s);
    if (!pfn) {
        ::WSASetLastError(WSAEOPNOTSUPP);
        return -1;
    }

    ::WSABUF bufs[k_max_iov];
    ::ULONG  n     = (msg->msg_iovlen < k_max_iov) ? msg->msg_iovlen : k_max_iov;
    ::WSAMSG wm    = msg->to_wsamsg(bufs, n);
    ::DWORD  bytes = 0;
    int      rc    = pfn(s, &wm, 0, &bytes, nullptr, nullptr);
    return rc == 0 ? static_cast<int>(bytes) : -1;
}

// ---- getsockopt / setsockopt -----------------------------------------------
// WinSock2 requires char* instead of void* for option value pointers.
// These overloads insert the required cast so call sites compile unchanged.

inline int getsockopt(::SOCKET s, int level, int name, void* val, socklen_t* len) noexcept {
    return ::getsockopt(s, level, name, static_cast<char*>(val), len);
}
inline int setsockopt(::SOCKET s, int level, int name, const void* val, socklen_t len) noexcept {
    return ::setsockopt(s, level, name, static_cast<const char*>(val), len);
}

#else // ---- POSIX (Linux / macOS) ------------------------------------------

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

inline int sock_errno() noexcept { return errno; }

#endif // _MSC_VER

// ----------------------------------------------------------------------------

#endif
