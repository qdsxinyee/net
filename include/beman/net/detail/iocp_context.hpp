// include/beman/net/detail/iocp_context.hpp                        -*-C++-*-
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef INCLUDED_BEMAN_NET_DETAIL_IOCP_CONTEXT
#define INCLUDED_BEMAN_NET_DETAIL_IOCP_CONTEXT

// This file is only meaningful on Windows / MSVC.
#ifdef _MSC_VER

// ----------------------------------------------------------------------------
// Overview
// --------
// iocp_context implements context_base using Windows I/O Completion Ports
// (IOCP).  It is selected at compile time when BEMAN_NET_USE_IOCP is defined,
// which is set by CMake when -DBEMAN_NET_WITH_IOCP=ON is passed.
//
// Key design decisions
// --------------------
//
// 1. iocp_op / OVERLAPPED lifetime
//    Every pending async operation is represented by an iocp_op object that
//    embeds an OVERLAPPED as its *first* member.  GetQueuedCompletionStatus
//    returns a pointer to that OVERLAPPED; we recover the enclosing iocp_op
//    via reinterpret_cast (safe because OVERLAPPED is at offset 0).
//    Each iocp_op also stores an op_kind tag so run_one() can dispatch the
//    completion without RTTI / dynamic_cast.
//
// 2. native_handle_type vs SOCKET
//    netfwd.hpp defines native_handle_type as std::uintptr_t on Windows
//    (changed from int to avoid truncating the 64-bit SOCKET value).
//    iocp_record stores the real SOCKET; socket_of() converts a socket_id
//    to a SOCKET through the record table.
//
// 3. AcceptEx quirks
//    AcceptEx requires the accept socket to be created before the call, and
//    needs a caller-supplied buffer for local + remote addresses.  We store
//    both in an accept_state held by io_base::extra (a unique_ptr<void>).
//
// 4. ConnectEx quirks
//    ConnectEx requires the connecting socket to be bound first.  We bind to
//    INADDR_ANY:0 implicitly (ensure_bound) when the socket has not been
//    explicitly bound yet.
//
// 5. WSARecvMsg / WSASendMsg
//    Both are Winsock extension functions that must be loaded dynamically via
//    WSAIoctl.  We cache the function pointers per-socket in iocp_record.
//    A plain WSARecv / WSASend fallback is used if loading fails.
//
// 6. Timers
//    Implemented identically to poll_context: a sorted_list keyed on
//    time_point, checked on every run_one() call.  The IOCP wait timeout is
//    derived from the nearest timer deadline so we never sleep longer than
//    needed.
//
// 7. WSAStartup / WSACleanup
//    Managed by an RAII wsa_guard member so the lifetime is tied to the
//    iocp_context object.
// ----------------------------------------------------------------------------

#include <beman/net/detail/platform.hpp>
#include <beman/net/detail/netfwd.hpp>
#include <beman/net/detail/container.hpp>
#include <beman/net/detail/context_base.hpp>
#include <beman/net/detail/sorted_list.hpp>
#include <cassert>
#include <chrono>
#include <iostream>
#include <vector>

// ----------------------------------------------------------------------------

namespace beman::net::detail {
struct iocp_record;
struct iocp_context;
} // namespace beman::net::detail

// ----------------------------------------------------------------------------
// iocp_op
// Wraps OVERLAPPED together with a back-pointer to the logical io_base and
// a tag that identifies the operation kind so run_one() can dispatch without
// RTTI.
// ----------------------------------------------------------------------------

namespace beman::net::detail {

enum class iocp_op_kind : unsigned char { accept, connect, receive, send, timer };

struct iocp_op {
    OVERLAPPED   overlapped{}; // MUST be first - reinterpret_cast relies on it
    io_base*     base{nullptr};
    iocp_op_kind kind{};
    ::DWORD      flags{0};

    explicit iocp_op(io_base* b, iocp_op_kind k) : base(b), kind(k) {}
};

} // namespace beman::net::detail

// ----------------------------------------------------------------------------
// iocp_record
// Per-socket state stored in the container<> indexed by socket_id.
// ----------------------------------------------------------------------------

struct beman::net::detail::iocp_record {
    ::SOCKET          socket{INVALID_SOCKET};
    bool              bound{false};

    explicit iocp_record(::SOCKET s) : socket(s) {}
};

// ----------------------------------------------------------------------------
// iocp_context
// ----------------------------------------------------------------------------

struct beman::net::detail::iocp_context final : ::beman::net::detail::context_base {
  private:
    // ------------------------------------------------------------------
    // Types
    // ------------------------------------------------------------------
    using time_t       = ::std::chrono::system_clock::time_point;
    using timer_node_t = ::beman::net::detail::context_base::resume_at_operation;

    struct get_time {
        auto operator()(auto* t) const -> time_t { return ::std::get<0>(*t); }
    };
    using timer_priority_t = ::beman::net::detail::sorted_list<timer_node_t, ::std::less<>, get_time>;

    // ------------------------------------------------------------------
    // RAII Winsock initialisation
    // ------------------------------------------------------------------
    struct wsa_guard {
        wsa_guard() {
            ::WSADATA wd{};
            if (::WSAStartup(MAKEWORD(2, 2), &wd) != 0)
                throw ::std::system_error(::WSAGetLastError(), ::std::system_category(), "WSAStartup failed");
        }
        ~wsa_guard() { ::WSACleanup(); }
        wsa_guard(const wsa_guard&)            = delete;
        wsa_guard& operator=(const wsa_guard&) = delete;
    } d_wsa; // constructed first, destroyed last

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------
    ::HANDLE                                                           d_iocp{INVALID_HANDLE_VALUE};
    ::beman::net::detail::container<::beman::net::detail::iocp_record> d_sockets;
    timer_priority_t                                                   d_timeouts;
    ::beman::net::detail::context_base::task*                          d_tasks{nullptr};

    //Record the number of asynchronous I/O operations submitted to the kernel.
    ::std::size_t                                                      d_outstanding_io{0};

    //Keep track of the number of currently active sockets to prevent the event loop from terminating prematurely
    ::std::size_t                                                      d_socket_count{0};

    // Helper: change d_outstanding_io with logging
    auto inc_outstanding(const char* reason) -> void {
        ++this->d_outstanding_io;
        ::std::cout << "[iocp] outstanding++ (" << reason << ") -> " << this->d_outstanding_io << "\n";
    }
    auto dec_outstanding(const char* reason) -> void {
        --this->d_outstanding_io;
        ::std::cout << "[iocp] outstanding-- (" << reason << ") -> " << this->d_outstanding_io << "\n";
    }

    struct deferred_io_task : context_base::task {
        iocp_context* ctx;
        io_base*      base;
        ::DWORD       bytes;
        deferred_io_task(iocp_context* c, io_base* b, ::DWORD by)
            : ctx(c), base(b), bytes(by) {
            ctx->inc_outstanding("deferred_io_task ctor");
        }
        auto complete() -> void override {
            ctx->dec_outstanding("deferred_io_task::complete");
            ctx->m_current_bytes = this->bytes;
            ctx->m_current_error = 0;
            if (this->base->work)
                this->base->work(*ctx, this->base);
            delete this;
        }
    };

  public:
    // Used to temporarily store the system state for the Lambda closure after run_one() parsing completes
    ::DWORD                                                            m_current_bytes{0};
    int                                                                m_current_error{0};  

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    auto socket_of(::beman::net::detail::socket_id id) -> ::SOCKET { return this->d_sockets[id].socket; }

    auto associate(::SOCKET s) -> bool {
        if (::CreateIoCompletionPort(reinterpret_cast<HANDLE>(s), this->d_iocp, 0, 0) == nullptr)
            return false;
        // FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: when WSARecv/WSASend completes
        // synchronously (rc==0), Windows will NOT post an IOCP completion packet.
        // This prevents double-completion: our deferred_io_task handles rc==0,
        // and without this flag the kernel would also post a completion for the
        // same iocp_op we already deleted, causing a use-after-free crash.
        ::SetFileCompletionNotificationModes(
            reinterpret_cast<HANDLE>(s),
            FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
        return true;
    }

    static auto make_op(::beman::net::detail::io_base* base, ::beman::net::detail::iocp_op_kind kind)
        -> ::beman::net::detail::iocp_op* {
        return new ::beman::net::detail::iocp_op(base, kind);
    }

    auto iocp_timeout_ms(const time_t& now) noexcept -> ::DWORD {
        if (this->d_timeouts.empty())
            return INFINITE;
        auto next = ::std::get<0>(*this->d_timeouts.front());
        if (next <= now)
            return 0;
        auto ms = ::std::chrono::duration_cast<::std::chrono::milliseconds>(next - now).count();
        return static_cast<::DWORD>(ms < 0 ? 0 : ms);
    }

    auto process_task() -> ::std::size_t {
        if (!this->d_tasks)
            return 0u;
        auto* tsk     = this->d_tasks;
        this->d_tasks = tsk->next;
        ::std::cout << "[iocp] process_task() executing task\n";
        tsk->complete();
        ::std::cout << "[iocp] process_task() task done, outstanding=" 
                    << this->d_outstanding_io << " sockets=" << this->d_socket_count << "\n";
        return 1u;
    }

    auto process_timeout(const time_t& now) -> ::std::size_t {
        if (!this->d_timeouts.empty() && ::std::get<0>(*this->d_timeouts.front()) <= now) {
            this->d_timeouts.pop_front()->complete();
            return 1u;
        }
        return 0u;
    }

    static auto load_accept_ex(::SOCKET s) noexcept -> ::LPFN_ACCEPTEX {
        ::LPFN_ACCEPTEX fn   = nullptr;
        ::GUID          guid = WSAID_ACCEPTEX;
        ::DWORD         n    = 0;
        ::WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &fn, sizeof(fn), &n, nullptr, nullptr);
        return fn;
    }

    static auto load_connect_ex(::SOCKET s) noexcept -> ::LPFN_CONNECTEX {
        ::LPFN_CONNECTEX fn   = nullptr;
        ::GUID           guid = WSAID_CONNECTEX;
        ::DWORD          n    = 0;
        ::WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &fn, sizeof(fn), &n, nullptr, nullptr);
        return fn;
    }

    // Bind to INADDR_ANY:0 if the socket has not been bound yet.
    // ConnectEx requires a prior bind.
    auto ensure_bound(::beman::net::detail::socket_id id) -> bool {
        auto& rec = this->d_sockets[id];
        if (rec.bound)
            return true;
        ::sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = 0;
        if (::bind(rec.socket, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
            return false;
        rec.bound = true;
        return true;
    }

    // Dispatch a completion to the appropriate io_base.
    // bytes is the number of bytes transferred (for receive / send).
    auto dispatch(::beman::net::detail::iocp_op* op, ::DWORD bytes, bool ok) -> void {
        auto* base = op->base;
        this->m_current_bytes = bytes;
        this->m_current_error = ok ? 0 : static_cast<int>(::GetLastError());

        delete op;
        dec_outstanding("dispatch (IOCP completion)");

        if (base->work) {
            ::std::cout << "[iocp] dispatch calling work, bytes=" << bytes 
                        << " err=" << this->m_current_error << "\n";
            ::std::cout.flush();
            try {
                base->work(*this, base);
            } catch (const std::exception& e) {
                ::std::cout << "[iocp] dispatch work threw exception: " << e.what() << "\n";
                ::std::cout.flush();
            } catch (...) {
                ::std::cout << "[iocp] dispatch work threw unknown exception\n";
                ::std::cout.flush();
            }
            ::std::cout << "[iocp] dispatch work returned\n";
            ::std::cout.flush();
        } else {
            // 没有 work 回调（如 timer），直接处理
            if (!ok && this->m_current_error == ERROR_OPERATION_ABORTED) {
                base->cancel();
            } else if (!ok) {
                base->error(::std::error_code(this->m_current_error, ::std::system_category()));
            } else {
                base->complete();
            }
        }

    }

    // Stored in io_base::extra for the duration of an AcceptEx call.
    struct accept_state {
        ::SOCKET accept_sock{INVALID_SOCKET};
        char*    buf{nullptr};
    };

  public:
    // ------------------------------------------------------------------
    // Constructor / destructor
    // ------------------------------------------------------------------

    iocp_context() {
        this->d_iocp = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
        if (!this->d_iocp || this->d_iocp == INVALID_HANDLE_VALUE)
            throw ::std::system_error(
                static_cast<int>(::GetLastError()), ::std::system_category(), "CreateIoCompletionPort failed");
    }

    ~iocp_context() override {
        if (this->d_iocp && this->d_iocp != INVALID_HANDLE_VALUE)
            ::CloseHandle(this->d_iocp);
    }

    // ------------------------------------------------------------------
    // context_base - socket management
    // ------------------------------------------------------------------

    auto make_socket(int fd) -> ::beman::net::detail::socket_id override {
        ::SOCKET s = static_cast<::SOCKET>(fd);
        this->associate(s);
        ++this->d_socket_count;
        return this->d_sockets.insert(::beman::net::detail::iocp_record(s));
    }

    auto make_socket(int domain, int type, int protocol, ::std::error_code& error)
        -> ::beman::net::detail::socket_id override {
        // WSA_FLAG_OVERLAPPED is required for IOCP.
        ::SOCKET s = ::WSASocketW(domain, type, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (s == INVALID_SOCKET) {
            error = ::std::error_code(::WSAGetLastError(), ::std::system_category());
            return ::beman::net::detail::socket_id::invalid;
        }
        if (!this->associate(s)) {
            error = ::std::error_code(static_cast<int>(::GetLastError()), ::std::system_category());
            ::closesocket(s);
            return ::beman::net::detail::socket_id::invalid;
        }

        ++this->d_socket_count;

        return this->d_sockets.insert(::beman::net::detail::iocp_record(s));
    }

    // Internal overload that accepts a SOCKET directly, avoiding the int truncation.
    auto make_socket_from_handle(::SOCKET s) -> ::beman::net::detail::socket_id {
         this->associate(s);
         ++this->d_socket_count;
         return this->d_sockets.insert(::beman::net::detail::iocp_record(s));
    }

    auto release(::beman::net::detail::socket_id id, ::std::error_code& error) -> void override {
        ::SOCKET s = this->socket_of(id);
        this->d_sockets.erase(id);
        if (::closesocket(s) == SOCKET_ERROR)
            error = ::std::error_code(::WSAGetLastError(), ::std::system_category());

        --this->d_socket_count;
        ::std::cout << "[iocp] release() socket_count -> " << this->d_socket_count 
                    << " outstanding=" << this->d_outstanding_io << "\n";
    }

    auto native_handle(::beman::net::detail::socket_id id) -> ::beman::net::detail::native_handle_type override {
        return static_cast<::beman::net::detail::native_handle_type>(this->socket_of(id));
    }

    auto set_option(::beman::net::detail::socket_id id,
                    int                             level,
                    int                             name,
                    const void*                     data,
                    ::socklen_t                     size,
                    ::std::error_code&              error) -> void override {
        if (::setsockopt(this->socket_of(id), level, name, static_cast<const char*>(data), size) == SOCKET_ERROR)
            error = ::std::error_code(::WSAGetLastError(), ::std::system_category());
    }

    auto bind(::beman::net::detail::socket_id id, const ::beman::net::detail::endpoint& ep, ::std::error_code& error)
        -> void override {
        if (::bind(this->socket_of(id), ep.data(), ep.size()) == SOCKET_ERROR) {
            error = ::std::error_code(::WSAGetLastError(), ::std::system_category());
            return;
        }
        this->d_sockets[id].bound = true;
    }

    auto listen(::beman::net::detail::socket_id id, int backlog, ::std::error_code& error) -> void override {
        if (::listen(this->socket_of(id), backlog) == SOCKET_ERROR)
            error = ::std::error_code(::WSAGetLastError(), ::std::system_category());
    }

    // ------------------------------------------------------------------
    // context_base - event loop
    // ------------------------------------------------------------------

    auto run_one() -> ::std::size_t override {

        ::std::cout << "[iocp] run_one() called, outstanding=" 
                    << this->d_outstanding_io 
                    << " sockets=" << this->d_socket_count << "\n";
        auto now = ::std::chrono::system_clock::now();

        if (0u < this->process_timeout(now) || 0u < this->process_task())
            return 1u;

        if (this->d_timeouts.empty() && !this->d_tasks && this->d_outstanding_io == 0 && this->d_socket_count == 0)
        {
            ::std::cout << "[iocp] run_one returning 0 (top-check): outstanding=" 
                        << this->d_outstanding_io << " sockets=" << this->d_socket_count << "\n";
            return ::std::size_t{};
        }

        while (true) {
            now                    = ::std::chrono::system_clock::now();
            ::DWORD     timeout_ms = this->iocp_timeout_ms(now);
            ::DWORD     bytes      = 0;
            ::ULONG_PTR key        = 0;
            OVERLAPPED* ov         = nullptr;

            ::BOOL ok = ::GetQueuedCompletionStatus(this->d_iocp, &bytes, &key, &ov, timeout_ms);
            ::std::cout << "[iocp] GQCS returned ok=" << ok 
                        << " ov=" << (void*)ov 
                        << " bytes=" << bytes 
                        << " err=" << ::GetLastError() << "\n";
            if (ov == nullptr) {
                // Timeout or wakeup with no real completion.
                if (0u < this->process_timeout(::std::chrono::system_clock::now()))
                    return 1u;
                if (0u < this->process_task())
                    return 1u;
                ::std::cout << "[iocp] run_one returning 0 via ov==nullptr, outstanding=" << this->d_outstanding_io << "\n";
                
                if (this->d_timeouts.empty() && !this->d_tasks && this->d_outstanding_io == 0 && this->d_socket_count == 0) 
                {
                    ::std::cout << "[iocp] run_one returning 0 (ov==nullptr): outstanding="
                                << this->d_outstanding_io << " sockets=" << this->d_socket_count << "\n";
                    return ::std::size_t{};
                }

                continue;
               // return ::std::size_t{};
            }

            // Recover our wrapper from the OVERLAPPED pointer.
            // Safe because OVERLAPPED is the first member of iocp_op.
            auto* op = reinterpret_cast<::beman::net::detail::iocp_op*>(ov);
            ::std::cout << "[iocp] dispatching ov=" << (void*)ov 
                        << " kind=" << static_cast<int>(op->kind)
                        << " base=" << (void*)op->base << "\n";
            this->dispatch(op, bytes, ok == TRUE);
            return 1u;
        }
    }

    auto wakeup() -> void {
        // Post a no-op completion to unblock a waiting thread.
        ::PostQueuedCompletionStatus(this->d_iocp, 0, 0, nullptr);
    }

    auto schedule(::beman::net::detail::context_base::task* tsk) -> void override {
        bool was_empty = (this->d_tasks == nullptr);
        tsk->next     = this->d_tasks;
        this->d_tasks = tsk;
        //this->wakeup();
        /*
        if(was_empty)
        {
            this->wakeup();
        }
        */
    }

    auto cancel(::beman::net::detail::io_base* cancel_op, ::beman::net::detail::io_base* op) -> void override {
        if (op->id == ::beman::net::detail::socket_id::invalid) 
        {
            // Timer: remove from queue and cancel synchronously
            ::std::cout << "[iocp] cancel() timer op\n";
            this->d_timeouts.erase(static_cast<timer_node_t*>(op));
            op->cancel();
        } else {
            // Socket IO: async cancel, wait for ERROR_OPERATION_ABORTED from IOCP
            ::std::cout << "[iocp] cancel() socket io op, calling CancelIoEx\n";
            ::SOCKET s = this->socket_of(op->id);
            if (s != INVALID_SOCKET) 
            {
                ::CancelIoEx(reinterpret_cast<::HANDLE>(s), nullptr);
            }
        }
        ::std::cout << "[iocp] cancel() calling cancel_op->cancel()\n";
        cancel_op->cancel();
        ::std::cout << "[iocp] cancel() done, outstanding=" << this->d_outstanding_io 
                    << " sockets=" << this->d_socket_count << "\n";
    }

    // ------------------------------------------------------------------
    // context_base - async operations
    // ------------------------------------------------------------------

    auto accept(::beman::net::detail::context_base::accept_operation* completion)
        -> ::beman::net::detail::submit_result override {

        ::std::cout << "[iocp] accept() called, d_outstanding_io=" << this->d_outstanding_io << "\n";
        ::std::cout << "[iocp] AcceptEx submitted\n";

        ::SOCKET listen_sock = this->socket_of(completion->id);

        // Determine address family from the listening socket.
        ::WSAPROTOCOL_INFOW info{};
        int                 info_len = sizeof(info);
        if (::getsockopt(listen_sock, SOL_SOCKET, SO_PROTOCOL_INFOW, reinterpret_cast<char*>(&info), &info_len) ==
            SOCKET_ERROR) {
            completion->error(::std::error_code(::WSAGetLastError(), ::std::system_category()));
            return ::beman::net::detail::submit_result::error;
        }

        // AcceptEx requires the accept socket to exist before the call.
        // Do NOT associate here - make_socket_from_handle in the work callback will do it.
        ::SOCKET accept_sock =
            ::WSASocketW(info.iAddressFamily, info.iSocketType, info.iProtocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (accept_sock == INVALID_SOCKET) {
            completion->error(::std::error_code(::WSAGetLastError(), ::std::system_category()));
            return ::beman::net::detail::submit_result::error;
        }

        ::LPFN_ACCEPTEX fn = load_accept_ex(listen_sock);
        if (!fn) {
            ::closesocket(accept_sock);
            completion->error(::std::error_code(::WSAGetLastError(), ::std::system_category()));
            return ::beman::net::detail::submit_result::error;
        }

        static constexpr ::DWORD addr_buf_size = sizeof(::sockaddr_storage) + 16;
        auto*                    buf           = new char[2 * addr_buf_size];
        auto*                    op            = make_op(completion, ::beman::net::detail::iocp_op_kind::accept);
        ::DWORD                  bytes_rx      = 0;

        // Set up the work callback that will be invoked by dispatch()
        // once the kernel signals the accept completion.
        completion->work = [](::beman::net::detail::context_base& ctx,
                              ::beman::net::detail::io_base*      base) -> ::beman::net::detail::submit_result {
            ::std::cout << "[iocp] accept complete, new socket registered\n";

            auto& iocp_ctx = static_cast<iocp_context&>(ctx);
            auto* cmp      = static_cast<accept_operation*>(base);
            auto* st       = static_cast<accept_state*>(cmp->extra.get());

            if (iocp_ctx.m_current_error == ERROR_OPERATION_ABORTED || iocp_ctx.m_current_error == WSAECONNRESET) {
                cmp->cancel();
                return ::beman::net::detail::submit_result::ready;
            } else if (iocp_ctx.m_current_error != 0) {
                cmp->error(::std::error_code(iocp_ctx.m_current_error, ::std::system_category()));
                return ::beman::net::detail::submit_result::error;
            }
            // Update the accept socket to inherit the listener's properties.
            ::SOCKET listen_s = iocp_ctx.socket_of(cmp->id);
            ::setsockopt(st->accept_sock,
                         SOL_SOCKET,
                         SO_UPDATE_ACCEPT_CONTEXT,
                         reinterpret_cast<char*>(&listen_s),
                         sizeof(::SOCKET));

            // Transfer ownership of the accept socket to the context.
            ::SOCKET accepted   = st->accept_sock;
            st->accept_sock     = INVALID_SOCKET; // prevent double-close
            ::std::get<2>(*cmp) = iocp_ctx.make_socket_from_handle(accepted);


            cmp->extra.reset(); // release accept_state
            

            ::std::cout << "[iocp] calling accept cmp->complete()\n";
            cmp->complete();

            ::std::cout << "[iocp] after cmp->complete(), returning\n";
            return ::beman::net::detail::submit_result::ready;
        };

        // Store accept_sock + address buffer in io_base::extra so they
        // survive until the IOCP completion arrives.

        completion->extra = {new accept_state{accept_sock, buf}, +[](void* p) {
                                 auto* st = static_cast<accept_state*>(p);
                                 // If still valid at destruction time, close the socket.
                                 // Normally ownership is transferred to make_socket before
                                 // this deleter runs.
                                 if (st->accept_sock != INVALID_SOCKET)
                                     ::closesocket(st->accept_sock);
                                 delete[] st->buf;
                                 delete st;
                             }};


        ::BOOL ok = fn(listen_sock,
                       accept_sock,
                       buf,
                       0, // dwReceiveDataLength
                       addr_buf_size,
                       addr_buf_size,
                       &bytes_rx,
                       &op->overlapped);
        
        if (!ok && ::WSAGetLastError() != ERROR_IO_PENDING) {
            delete[] buf;
            delete op;
            ::closesocket(accept_sock);
            completion->error(::std::error_code(::WSAGetLastError(), ::std::system_category()));
            return ::beman::net::detail::submit_result::error;
        }

        inc_outstanding("accept submitted");

        return ::beman::net::detail::submit_result::submit;
    }

    // ------------------------------------------------------------------

    auto connect(::beman::net::detail::context_base::connect_operation* op)
        -> ::beman::net::detail::submit_result override {

        ::SOCKET s = this->socket_of(op->id);

        if (!this->ensure_bound(op->id)) {
            op->error(::std::error_code(::WSAGetLastError(), ::std::system_category()));
            return ::beman::net::detail::submit_result::error;
        }

        ::LPFN_CONNECTEX fn = load_connect_ex(s);
        if (!fn) {
            op->error(::std::error_code(::WSAGetLastError(), ::std::system_category()));
            return ::beman::net::detail::submit_result::error;
        }

        // After ConnectEx completes, SO_UPDATE_CONNECT_CONTEXT is required
        // before the socket can be used for send / receive.
        op->work = [](::beman::net::detail::context_base& ctx,
                      ::beman::net::detail::io_base*      base) -> ::beman::net::detail::submit_result {
            auto& iocp_ctx = static_cast<iocp_context&>(ctx);

            // Explicitly cast nullptr to const char* to avoid an ambiguous overload (C2668).
            // platform.hpp provides a POSIX-compatible setsockopt taking const void*, which
            // conflicts with the native Winsock version (const char*) when passing nullptr.
            auto& iocp = static_cast<iocp_context&>(ctx);
            if (iocp.m_current_error == ERROR_OPERATION_ABORTED) {
                base->cancel();
                return ::beman::net::detail::submit_result::ready;
            } else if (iocp.m_current_error != 0) {
                base->error(::std::error_code(iocp.m_current_error, ::std::system_category()));
                return ::beman::net::detail::submit_result::error;
            }
            ::setsockopt(iocp_ctx.socket_of(base->id),
                         SOL_SOCKET,
                         SO_UPDATE_CONNECT_CONTEXT,
                         static_cast<const char*>(nullptr),
                         0);
            base->complete();
            return ::beman::net::detail::submit_result::ready;
        };

        const auto& ep         = ::std::get<0>(*op);
        auto*       iocp_op_   = make_op(op, ::beman::net::detail::iocp_op_kind::connect);
        ::DWORD     bytes_sent = 0;

        ::BOOL ok = fn(s, ep.data(), ep.size(), nullptr, 0, &bytes_sent, &iocp_op_->overlapped);

        if (!ok && ::WSAGetLastError() != ERROR_IO_PENDING) {
            delete iocp_op_;
            op->error(::std::error_code(::WSAGetLastError(), ::std::system_category()));
            return ::beman::net::detail::submit_result::error;
        }

        inc_outstanding("connect submitted");

        return ::beman::net::detail::submit_result::submit;
    }

    // ------------------------------------------------------------------

    auto receive(::beman::net::detail::context_base::receive_operation* op)
        -> ::beman::net::detail::submit_result override {

        auto& rec      = this->d_sockets[op->id];
        auto* iocp_op_ = make_op(op, ::beman::net::detail::iocp_op_kind::receive);

        ::msghdr* msg   = &::std::get<0>(*op);
        iocp_op_->flags = static_cast<::DWORD>(::std::get<1>(*op));
        int       rc    = SOCKET_ERROR;

        op->work = [](::beman::net::detail::context_base& ctx, ::beman::net::detail::io_base* base) -> ::beman::net::detail::submit_result {
            auto& iocp = static_cast<iocp_context&>(ctx);
            auto* cmp  = static_cast<receive_operation*>(base);
            
            if (iocp.m_current_error == ERROR_OPERATION_ABORTED || iocp.m_current_error == WSAECONNRESET) {
                cmp->cancel();
                return ::beman::net::detail::submit_result::ready;
            } else if (iocp.m_current_error != 0) {
                cmp->error(::std::error_code(iocp.m_current_error, ::std::system_category()));
                return ::beman::net::detail::submit_result::error;
            }

            ::std::get<2>(*cmp) = static_cast<::std::size_t>(iocp.m_current_bytes);
            cmp->complete();
            return ::beman::net::detail::submit_result::ready;
        };

        ::WSABUF bufs[16];
        ::ULONG  n = (msg->msg_iovlen < 16) ? msg->msg_iovlen : 16;
        for (::ULONG i = 0; i < n; ++i)
                bufs[i] = static_cast<::WSABUF>(msg->msg_iov[i]);

        ::DWORD bytes_sync = 0;  
        rc = ::WSARecv(rec.socket, bufs, n, &bytes_sync, &iocp_op_->flags, &iocp_op_->overlapped, nullptr);
        ::std::cout << "[iocp] WSARecv submitted rc=" << rc 
            << " err=" << ::WSAGetLastError() << "\n";
        
        if (rc == 0) {
            ::std::cout << "[iocp] WSARecv sync complete, bytes=" << bytes_sync << ", using deferred_io_task\n";
            delete iocp_op_; 
            this->schedule(new deferred_io_task(this, op, bytes_sync));
            return ::beman::net::detail::submit_result::submit; 
        }
        
        
        if (rc == SOCKET_ERROR && ::WSAGetLastError() != WSA_IO_PENDING) {
            delete iocp_op_;
            op->error(::std::error_code(::WSAGetLastError(), ::std::system_category()));
            return ::beman::net::detail::submit_result::error;
        }

        inc_outstanding("WSARecv submitted async");

        return ::beman::net::detail::submit_result::submit;
    }

    // ------------------------------------------------------------------

    auto send(::beman::net::detail::context_base::send_operation* op) -> ::beman::net::detail::submit_result override {

        auto& rec      = this->d_sockets[op->id];
        auto* iocp_op_ = make_op(op, ::beman::net::detail::iocp_op_kind::send);

        op->work = [](::beman::net::detail::context_base& ctx, ::beman::net::detail::io_base* base) -> ::beman::net::detail::submit_result {
            auto& iocp = static_cast<iocp_context&>(ctx);
            auto* cmp  = static_cast<send_operation*>(base);
            
            if (iocp.m_current_error == ERROR_OPERATION_ABORTED) {
                cmp->cancel();
                return ::beman::net::detail::submit_result::ready;
            } else if (iocp.m_current_error != 0) {
                cmp->error(::std::error_code(iocp.m_current_error, ::std::system_category()));
                return ::beman::net::detail::submit_result::error;
            }

            ::std::get<2>(*cmp) = static_cast<::std::size_t>(iocp.m_current_bytes);
            cmp->complete();
            return ::beman::net::detail::submit_result::ready;
        };

        ::msghdr* msg   = &::std::get<0>(*op);
        int       rc    = SOCKET_ERROR;

        ::WSABUF bufs[16];
        ::ULONG  n = (msg->msg_iovlen < 16) ? msg->msg_iovlen : 16;
        for (::ULONG i = 0; i < n; ++i)
                bufs[i] = static_cast<::WSABUF>(msg->msg_iov[i]);

 
        ::DWORD bytes_sync = 0;
        rc = ::WSASend(rec.socket, bufs, n, &bytes_sync, 0, &iocp_op_->overlapped, nullptr);
        ::std::cout << "[iocp] WSASend submitted rc=" << rc
            << " err=" << ::WSAGetLastError() << "\n";
        
        if (rc == 0) {
            ::std::cout << "[iocp] WSASend sync complete, bytes=" << bytes_sync << ", using deferred_io_task\n";
            delete iocp_op_;
            this->schedule(new deferred_io_task(this, op, bytes_sync));
            return ::beman::net::detail::submit_result::submit;
        }
       
        
        if (rc == SOCKET_ERROR && ::WSAGetLastError() != WSA_IO_PENDING) {
            delete iocp_op_;
            op->error(::std::error_code(::WSAGetLastError(), ::std::system_category()));
            return ::beman::net::detail::submit_result::error;
        }

        inc_outstanding("WSASend submitted async");

        return ::beman::net::detail::submit_result::submit;
    }

    // ------------------------------------------------------------------

    auto resume_at(::beman::net::detail::context_base::resume_at_operation* op)
        -> ::beman::net::detail::submit_result override {

        op->id = ::beman::net::detail::socket_id::invalid;
            
        if (::std::chrono::system_clock::now() < ::std::get<0>(*op)) {
            this->d_timeouts.insert(op);
            return ::beman::net::detail::submit_result::submit;
        }
        op->complete();
        return ::beman::net::detail::submit_result::ready;
    }
};

// ----------------------------------------------------------------------------

#endif // _MSC_VER
#endif // INCLUDED_BEMAN_NET_DETAIL_IOCP_CONTEXT
