// include/beman/net/detail/poll_context.hpp                        -*-C++-*-
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef INCLUDED_BEMAN_NET_DETAIL_POLL_CONTEXT
#define INCLUDED_BEMAN_NET_DETAIL_POLL_CONTEXT

// ----------------------------------------------------------------------------

#include <beman/net/detail/platform.hpp>
#include <beman/net/detail/netfwd.hpp>
#include <beman/net/detail/container.hpp>
#include <beman/net/detail/context_base.hpp>
#include <beman/net/detail/sorted_list.hpp>
#include <vector>
#include <iostream>

// ----------------------------------------------------------------------------

namespace beman::net::detail {
struct poll_record;
struct poll_context;
} // namespace beman::net::detail

// ----------------------------------------------------------------------------

struct beman::net::detail::poll_record final {
    poll_record(::beman::net::detail::native_handle_type h) : handle(h) {}
    ::beman::net::detail::native_handle_type handle;
    bool                                     blocking{true};
};

// ----------------------------------------------------------------------------

struct beman::net::detail::poll_context final : ::beman::net::detail::context_base {
#ifdef _MSC_VER
    // On Windows, Winsock must be initialised before any socket call.
    // This RAII guard calls WSAStartup on construction and WSACleanup on
    // destruction, tying the Winsock lifetime to the poll_context object.
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
#endif

    using time_t       = ::std::chrono::system_clock::time_point;
    using timer_node_t = ::beman::net::detail::context_base::resume_at_operation;
    struct get_time {
        auto operator()(auto* t) const -> time_t { return ::std::get<0>(*t); }
    };
    using timer_priority_t = ::beman::net::detail::sorted_list<timer_node_t, ::std::less<>, get_time>;
    ::beman::net::detail::container<::beman::net::detail::poll_record> d_sockets;
    ::std::vector<::pollfd>                                            d_poll;
    ::std::vector<::beman::net::detail::io_base*>                      d_outstanding;
    timer_priority_t                                                   d_timeouts;
    ::beman::net::detail::context_base::task*                          d_tasks{};

    auto make_socket(int fd) -> ::beman::net::detail::socket_id override final { return this->d_sockets.insert(fd); }
    auto make_socket(int d, int t, int p, ::std::error_code& error) -> ::beman::net::detail::socket_id override final {
        // ::socket() returns SOCKET (ULONG_PTR) on Windows and int on POSIX.
        // INVALID_SOCKET / -1 are the respective failure sentinels.
#ifdef _MSC_VER
        ::SOCKET fd(::socket(d, t, p));
        if (fd == INVALID_SOCKET) {
            error = ::std::error_code(sock_errno(), ::std::system_category());
            return ::beman::net::detail::socket_id::invalid;
        }
        return this->make_socket(static_cast<int>(fd)); // narrowing is safe: stored as native_handle_type
#else
        int fd(::socket(d, t, p));
        if (fd < 0) {
            error = ::std::error_code(sock_errno(), ::std::system_category());
            return ::beman::net::detail::socket_id::invalid;
        }
        return this->make_socket(fd);
#endif
    }

    // Mark a registered socket as non-blocking so that add_outstanding() will
    // call work() immediately instead of going straight to poll().
    // Must be called after make_socket() whenever the underlying fd has been
    // put into non-blocking mode outside of this class (e.g. in accept's work
    // lambda on Windows where F_GETFL is unavailable).
    auto set_nonblocking(::beman::net::detail::socket_id id) -> void { this->d_sockets[id].blocking = false; }
    auto release(::beman::net::detail::socket_id id, ::std::error_code& error) -> void override final {
        ::beman::net::detail::native_handle_type handle(this->d_sockets[id].handle);
        this->d_sockets.erase(id);
        if (::close(handle) < 0) {
            error = ::std::error_code(sock_errno(), ::std::system_category());
        }
    }
    auto native_handle(::beman::net::detail::socket_id id) -> ::beman::net::detail::native_handle_type override final {
        return this->d_sockets[id].handle;
    }
    auto set_option(::beman::net::detail::socket_id id,
                    int                             level,
                    int                             name,
                    const void*                     data,
                    ::socklen_t                     size,
                    ::std::error_code&              error) -> void override final {
        if (::setsockopt(this->native_handle(id), level, name, data, size) < 0) {
            error = ::std::error_code(sock_errno(), ::std::system_category());
        }
    }
    auto bind(::beman::net::detail::socket_id       id,
              const ::beman::net::detail::endpoint& endpoint,
              ::std::error_code&                    error) -> void override final {
        if (::bind(this->native_handle(id), endpoint.data(), endpoint.size()) < 0) {
            error = ::std::error_code(sock_errno(), ::std::system_category());
        }
    }
    auto listen(::beman::net::detail::socket_id id, int no, ::std::error_code& error) -> void override final {
        if (::listen(this->native_handle(id), no) < 0) {
            error = ::std::error_code(sock_errno(), ::std::system_category());
        }
    }

    auto process_task() -> ::std::size_t {
        if (this->d_tasks) {
            auto* tsk{this->d_tasks};
            this->d_tasks = tsk->next;
            tsk->complete();
            return 1u;
        }
        return 0u;
    }
    auto process_timeout(const auto& now) -> ::std::size_t {
        if (!this->d_timeouts.empty() && ::std::get<0>(*this->d_timeouts.front()) <= now) {
            this->d_timeouts.pop_front()->complete();
            return 1u;
        }
        return 0u;
    }
    auto remove_outstanding(::std::size_t i) {
        if (i + 1u != this->d_poll.size()) {
            this->d_poll[i]        = this->d_poll.back();
            this->d_outstanding[i] = this->d_outstanding.back();
        }
        this->d_poll.pop_back();
        this->d_outstanding.pop_back();
    }
    auto to_milliseconds(auto duration) -> int {
        return int(::std::chrono::duration_cast<::std::chrono::milliseconds>(duration).count());
    }
    auto run_one() -> ::std::size_t override final {
        auto now{::std::chrono::system_clock::now()};
        if (0u < this->process_timeout(now) || 0 < this->process_task()) {
            return 1u;
        }
        if (this->d_poll.empty() && this->d_timeouts.empty()) {
            return ::std::size_t{};
        }
        while (true) {
            auto   next_time{this->d_timeouts.value_or(now)};
            int    timeout{now == next_time ? -1 : this->to_milliseconds(next_time - now)};
            nfds_t sz([](auto s) {
                if constexpr (::std::same_as<decltype(s), nfds_t>)
                    return s;
                else
                    return nfds_t(s);
            }(this->d_poll.size()));
            int    rc(::poll(this->d_poll.data(), sz, timeout));
            if (rc < 0) {
                // sock_errno() maps to WSAGetLastError() on Windows, errno on POSIX.
                // EINTR / EAGAIN macros are mapped to their WSA equivalents in platform.hpp.
                switch (sock_errno()) {
                default:
                    return ::std::size_t();
                case EINTR:
                case EAGAIN:
                    break;
                }
            } else {
                for (::std::size_t i(this->d_poll.size()); 0 < i--;) {
                    if (this->d_poll[i].revents & (this->d_poll[i].events | POLLERR  )) {
                        ::beman::net::detail::io_base* completion = this->d_outstanding[i];
                        this->remove_outstanding(i);
                        completion->work(*this, completion);
                        return ::std::size_t(1);
                    }
                }
                if (0u < this->process_timeout(::std::chrono::system_clock::now())) {
                    return 1u;
                }
            }
        }
        return ::std::size_t{};
    }
    auto wakeup() -> void {
        //-dk:TODO wake-up polling thread
    }

    auto add_outstanding(::beman::net::detail::io_base* completion) -> ::beman::net::detail::submit_result {
        auto id{completion->id};
        if (this->d_sockets[id].blocking ||
            completion->work(*this, completion) == ::beman::net::detail::submit_result::submit) {
            decltype(pollfd().events) events{};
            if (bool(completion->event & ::beman::net::event_type::in)) {
                events |= POLLIN;
            }
            if (bool(completion->event & ::beman::net::event_type::out)) {
                events |= POLLOUT;
            }
            // this->d_poll.emplace_back(::pollfd{this->native_handle(id), events, short()});
            //  pollfd::fd is int on POSIX and SOCKET (ULONG_PTR) on Windows.
            //  Cast through the actual field type to avoid narrowing warnings on
            //  both platforms without introducing a #ifdef here.
            this->d_poll.emplace_back(
                ::pollfd{static_cast<decltype(::pollfd{}.fd)>(this->native_handle(id)), events, short()});
            this->d_outstanding.emplace_back(completion);
            this->wakeup();
            return ::beman::net::detail::submit_result::submit;
        }
        return ::beman::net::detail::submit_result::ready;
    }

    auto cancel(::beman::net::detail::io_base* cancel_op, ::beman::net::detail::io_base* op) -> void override final {
        auto it(::std::find(this->d_outstanding.begin(), this->d_outstanding.end(), op));
        if (it != this->d_outstanding.end()) {
            this->remove_outstanding(std::size_t(::std::distance(this->d_outstanding.begin(), it)));
            op->cancel();
            cancel_op->cancel();
        } else if (this->d_timeouts.erase(op)) {
            op->cancel();
            cancel_op->cancel();
        } else {

#ifdef _MSC_VER
            // On Windows, accepted sockets are set non-blocking (blocking=false),
            // so add_outstanding() calls work() immediately. If work() returns
            // ready, op->complete() has already been called and op was never
            // inserted into d_outstanding or d_timeouts.
            // when_any then tries to cancel the peer op (e.g. the timeout timer)
            // which arrives here having already fired and been removed from its
            // queue. This is a normal completion-vs-cancellation race, not an
            // error. We only need to notify cancel_op so when_any can clean up;
            // op itself has already completed normally and needs no action.
            cancel_op->cancel();
#else
            // On Linux all accepted sockets remain blocking=true, so work() is
            // never called immediately and ops are always in a queue when
            // cancel() is called. Reaching here indicates a real bug.
            std::cerr << "ERROR: poll_context::cancel(): entity not cancelled!\n";
#endif
        }
    }
    auto schedule(::beman::net::detail::context_base::task* tsk) -> void override {
        tsk->next     = this->d_tasks;
        this->d_tasks = tsk;
    }
    auto accept(::beman::net::detail::context_base::accept_operation* completion)
        -> ::beman::net::detail::submit_result override final {
        completion->work = [](::beman::net::detail::context_base& ctxt, ::beman::net::detail::io_base* comp) {
            auto  id{comp->id};
            auto& cmp(*static_cast<accept_operation*>(comp));

            while (true) {
#ifdef _MSC_VER
                // On Windows, ::accept() returns SOCKET (ULONG_PTR).
                ::SOCKET rc = ::accept(ctxt.native_handle(id), ::std::get<0>(cmp).data(), &::std::get<1>(cmp));
                if (rc == INVALID_SOCKET) {
                    switch (sock_errno()) {
                    default:
                        cmp.error(::std::error_code(sock_errno(), ::std::system_category()));
                        return ::beman::net::detail::submit_result::error;
                    case WSAEINTR:
                        break; // retry
                    case WSAEWOULDBLOCK:
                        return ::beman::net::detail::submit_result::submit;
                    }
                } else {
                    // Put the new socket into non-blocking mode so that subsequent
                    // async_receive / async_send calls can attempt work() immediately
                    // instead of blocking the event loop.
                    // platform.hpp shims fcntl(F_SETFL, O_NONBLOCK) to ioctlsocket(FIONBIO).
                    ::fcntl(static_cast<int>(rc), F_SETFL, O_NONBLOCK);
                    auto new_id = ctxt.make_socket(static_cast<int>(rc));
                    // make_socket() cannot detect the non-blocking state on Windows
                    // (no F_GETFL equivalent), so we inform the context explicitly.
                    static_cast<poll_context&>(ctxt).set_nonblocking(new_id);
                    ::std::get<2>(cmp) = new_id;
                    cmp.complete();
                    return ::beman::net::detail::submit_result::ready;
                }
#else
                int rc = ::accept(ctxt.native_handle(id), ::std::get<0>(cmp).data(), &::std::get<1>(cmp));
                if (0 <= rc) {
                    ::std::get<2>(cmp) = ctxt.make_socket(rc);
                    cmp.complete();
                    return ::beman::net::detail::submit_result::ready;
                } else {
                    switch (sock_errno()) {
                    default:
                        cmp.error(::std::error_code(sock_errno(), ::std::system_category()));
                        return ::beman::net::detail::submit_result::error;
                    case EINTR:
                        break;
                    case EWOULDBLOCK:
                        return ::beman::net::detail::submit_result::submit;
                    }
                }
#endif
            }
        };
        return this->add_outstanding(completion);
    }
    auto connect(::beman::net::detail::context_base::connect_operation* op)
        -> ::beman::net::detail::submit_result override {
        auto        handle{this->native_handle(op->id)};
        const auto& endpoint(::std::get<0>(*op));
        if (-1 == ::fcntl(handle, F_SETFL, O_NONBLOCK)) {
            op->error(::std::error_code(sock_errno(), ::std::system_category()));
            return ::beman::net::detail::submit_result::error;
        }
        if (0 == ::connect(handle, endpoint.data(), endpoint.size())) {
            op->complete();
            return ::beman::net::detail::submit_result::ready;
        }
#ifdef _MSC_VER
        // On Windows we must also update the blocking flag in the socket record
        // because F_GETFL is unavailable and make_socket() defaults to blocking=true.
        this->set_nonblocking(op->id);
#endif
        switch (sock_errno()) {
        default:
            op->error(::std::error_code(sock_errno(), ::std::system_category()));
            return ::beman::net::detail::submit_result::error;
        case EINPROGRESS:
#ifdef _MSC_VER
        // On Windows a non-blocking connect in progress reports WSAEWOULDBLOCK,
        // not EINPROGRESS (the two are distinct Winsock error codes even though
        // platform.hpp maps EINPROGRESS -> WSAEINPROGRESS for other purposes).
        case WSAEWOULDBLOCK:
#endif
        case EINTR:
            break;
        }

        op->context = this;
        op->work    = [](::beman::net::detail::context_base& ctxt, ::beman::net::detail::io_base* o) {
            auto hndl{ctxt.native_handle(o->id)};

            int         error{};
            ::socklen_t len{sizeof(error)};
            if (-1 == ::getsockopt(hndl, SOL_SOCKET, SO_ERROR, &error, &len)) {
                o->error(::std::error_code(sock_errno(), ::std::system_category()));
                return ::beman::net::detail::submit_result::error;
            }
            if (0 == error) {
                o->complete();
                return ::beman::net::detail::submit_result::ready;
            } else {
                o->error(::std::error_code(error, ::std::system_category()));
                return ::beman::net::detail::submit_result::error;
            }
        };

        return this->add_outstanding(op);
    }
    auto receive(::beman::net::detail::context_base::receive_operation* op)
        -> ::beman::net::detail::submit_result override {
        op->context = this;
        op->work    = [](::beman::net::detail::context_base& ctxt, ::beman::net::detail::io_base* o) {
            auto& completion(*static_cast<receive_operation*>(o));
            while (true) {
                auto rc{::recvmsg(ctxt.native_handle(o->id), &::std::get<0>(completion), ::std::get<1>(completion))};
                if (0 <= rc) {
                    ::std::get<2>(completion) = ::std::size_t(rc);
                    completion.complete();
                    return ::beman::net::detail::submit_result::ready;
                } else
                    switch (sock_errno()) {
                    default:
                        completion.error(::std::error_code(sock_errno(), ::std::system_category()));
                        return ::beman::net::detail::submit_result::error;
                    case ECONNRESET:
                    case EPIPE:
                        ::std::get<2>(completion) = 0u;
                        completion.complete();
                        return ::beman::net::detail::submit_result::ready;
                    case EINTR:
                        break;
                    case EWOULDBLOCK:
                        return ::beman::net::detail::submit_result::submit;
                    }
            }
        };
        return this->add_outstanding(op);
    }
    auto send(::beman::net::detail::context_base::send_operation* op) -> ::beman::net::detail::submit_result override {
        op->context = this;
        op->work    = [](::beman::net::detail::context_base& ctxt, ::beman::net::detail::io_base* o) {
            auto& completion(*static_cast<send_operation*>(o));

            while (true) {
                auto rc{::sendmsg(ctxt.native_handle(o->id), &::std::get<0>(completion), ::std::get<1>(completion))};
                if (0 <= rc) {
                    ::std::get<2>(completion) = ::std::size_t(rc);
                    completion.complete();
                    return ::beman::net::detail::submit_result::ready;
                } else
                    switch (sock_errno()) {
                    default:
                        completion.error(::std::error_code(sock_errno(), ::std::system_category()));
                        return ::beman::net::detail::submit_result::error;
                    case ECONNRESET:
                    case EPIPE:
                        ::std::get<2>(completion) = 0u;
                        completion.complete();
                        return ::beman::net::detail::submit_result::ready;
                    case EINTR:
                        break;
                    case EWOULDBLOCK:
                        return ::beman::net::detail::submit_result::submit;
                    }
            }
        };
        return this->add_outstanding(op);
    }
    auto resume_at(::beman::net::detail::context_base::resume_at_operation* op)
        -> ::beman::net::detail::submit_result override {
        if (::std::chrono::system_clock::now() < ::std::get<0>(*op)) {
            this->d_timeouts.insert(op);
            return ::beman::net::detail::submit_result::submit;
        } else {
            op->complete();
            return ::beman::net::detail::submit_result::ready;
        }
    }
};

// ----------------------------------------------------------------------------

#endif
