# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Anonymous diagnostic HTTP with bounded network reads (also embedded in PoCs)."""

import errno
import select
import socket
import ssl
import threading
import time

import requests
from requests.adapters import HTTPAdapter
from requests.auth import AuthBase
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import NameResolutionError, NewConnectionError
from urllib3.util.connection import allowed_gai_family


class AnonymousAuth(AuthBase):
    """Never attach operator credentials to diagnostic requests."""

    def __call__(self, prepared):
        for name in ("Authorization", "Cookie", "Proxy-Authorization"):
            prepared.headers.pop(name, None)
        return prepared


class RequestCancelled(requests.RequestException):
    pass


def _wait(connection, writing):
    """Wait up to 50 ms until the connection is readable, or (writing) writable or failed.

    select() raises ValueError for a descriptor of 1024 or more on Linux and macOS, which a dashboard with many
    open sockets reaches, so those fall back to poll().
    """
    try:
        if writing:
            _, writable, exceptional = select.select([], [connection], [connection], .05)
            return bool(writable or exceptional)
        return bool(select.select([connection], [], [], .05)[0])
    except ValueError:
        if not hasattr(select, "poll"):
            raise
    poller = select.poll()
    poller.register(connection, select.POLLOUT if writing else select.POLLIN)
    return bool(poller.poll(50))


class _RequestDeadline:
    """Interrupt active socket I/O, including headers, TLS and partial chunks.

    A duplicate keeps ownership across SSL's replacement of the original socket.
    Only the calling thread runs Requests; the joined watchdog never reads it.
    OS name resolution is outside this network-I/O deadline.
    """

    def __init__(self, timeout, should_stop):
        self.expires = time.monotonic() + timeout
        self.should_stop = should_stop or (lambda: False)
        self.done = threading.Event()
        self.lock = threading.Lock()
        self.sockets = []
        self.reason = None
        self.watcher = threading.Thread(target=self._watch, name="autopwn-http-deadline", daemon=True)

    def _watch(self):
        while not self.done.wait(min(.05, max(0, self.expires - time.monotonic()))):
            reason = "cancelled" if self.should_stop() else "timeout" if time.monotonic() >= self.expires else None
            if reason:
                with self.lock:
                    self.reason = reason
                    for connection in self.sockets:
                        try:
                            connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                return

    def check(self):
        if self.reason == "cancelled" or self.should_stop():
            raise RequestCancelled("Web request stopped")
        if self.reason == "timeout" or time.monotonic() >= self.expires:
            raise requests.Timeout("Web request network deadline exceeded")

    def track(self, connection):
        with self.lock:
            self.check()
            self.sockets.append(connection.dup())

    def __enter__(self):
        self.check()
        self.watcher.start()
        return self

    def __exit__(self, *_):
        self.done.set()
        self.watcher.join()
        for connection in self.sockets:
            connection.close()


class _DeadlineAdapter(HTTPAdapter):
    def __init__(self, deadline):
        class DeadlineTLS(ssl.SSLContext):
            def wrap_socket(self, sock, **kwargs):
                handshake = kwargs.pop("do_handshake_on_connect", True)
                secure = super().wrap_socket(sock, do_handshake_on_connect=False, **kwargs)
                try:
                    if handshake:
                        timeout = secure.gettimeout()
                        secure.setblocking(False)
                        while True:
                            deadline.check()
                            try:
                                secure.do_handshake()
                                break
                            except ssl.SSLWantReadError:
                                _wait(secure, False)
                            except ssl.SSLWantWriteError:
                                _wait(secure, True)
                        secure.settimeout(timeout)
                    return secure
                except BaseException:
                    secure.close()
                    raise

        self.tls_context_class = DeadlineTLS
        # Pool classes are instance-local: unrelated HTTP clients are untouched.
        class TrackedConnection:
            def _new_conn(self):
                # urllib3's blocking connect can spend the full timeout on each
                # resolved address. Poll nonblocking connects against one budget.
                try:
                    addresses = socket.getaddrinfo(self._dns_host, self.port, allowed_gai_family(), socket.SOCK_STREAM)
                except (socket.gaierror, UnicodeError) as error:  # an empty or over-long label fails IDNA here, not in urllib3
                    raise NameResolutionError(self.host, self, error) from error
                error = OSError("No target addresses resolved")
                pending = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR, 10035, 10036, 10037}
                for family, kind, protocol, _, address in addresses:
                    deadline.check()
                    connection = None
                    try:
                        connection = socket.socket(family, kind, protocol)
                        for option in self.socket_options or []:
                            connection.setsockopt(*option)
                        if self.source_address:
                            connection.bind(self.source_address)
                        connection.setblocking(False)
                        result = connection.connect_ex(address)
                        if result not in (0, errno.EISCONN) and result not in pending:
                            raise OSError(result, "Target connection failed")
                        while result in pending:
                            deadline.check()
                            if _wait(connection, True):
                                result = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                                if result:
                                    raise OSError(result, "Target connection failed")
                        deadline.check()
                        connection.settimeout(self.timeout)
                        deadline.track(connection)
                        return connection
                    except OSError as failure:
                        error = failure
                        if connection is not None:
                            connection.close()
                    except BaseException:
                        if connection is not None:
                            connection.close()
                        raise
                deadline.check()
                raise NewConnectionError(self, "Failed to establish target connection") from error

        class TrackedHTTP(TrackedConnection, HTTPConnection):
            pass

        class TrackedHTTPS(TrackedConnection, HTTPSConnection):
            pass

        class HTTPPool(HTTPConnectionPool):
            ConnectionCls = TrackedHTTP

        class HTTPSPool(HTTPSConnectionPool):
            ConnectionCls = TrackedHTTPS

        self.pool_classes = {"http": HTTPPool, "https": HTTPSPool}
        super().__init__(max_retries=0)
        self.poolmanager.pool_classes_by_scheme = self.pool_classes

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        host, pool = super().build_connection_pool_key_attributes(request, verify, cert)
        if host["scheme"] == "https":
            context = self.tls_context_class(ssl.PROTOCOL_TLS_CLIENT)
            # urllib3 applies cert_reqs and performs hostname matching. Preserve
            # Requests' CA/cert parameters while making only the handshake pollable.
            context.check_hostname = False
            context.hostname_checks_common_name = False
            pool["ssl_context"] = context
        return host, pool

    def proxy_manager_for(self, proxy, **kwargs):
        manager = super().proxy_manager_for(proxy, **kwargs)
        manager.pool_classes_by_scheme = self.pool_classes
        return manager


def read_response(call, *args, max_bytes=1048576, timeout=10, should_stop=None, **kwargs):
    """Read a prefix, never import ambient auth, and close every owned resource.

    Requests API functions use a private session/adapter. An injected transport
    is a test seam; it must implement the same nonblocking/bounded contract.
    """
    with _RequestDeadline(timeout, should_stop) as deadline, requests.Session() as session:
        session.trust_env = False
        adapter = _DeadlineAdapter(deadline)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        if call is None or call is requests.request:
            send = session.request
        elif call is requests.get:
            send = session.get
        else:
            send = call
        kwargs["auth"] = AnonymousAuth()
        response = None
        body = bytearray()
        try:
            deadline.check()
            response = send(*args, stream=True, timeout=timeout, **kwargs)
            response.autopwn_truncated = False
            for chunk in response.iter_content(chunk_size=8192):
                deadline.check()
                if not chunk:
                    continue
                remaining = max_bytes - len(body)
                body.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    response.autopwn_truncated = True
                    break
            deadline.check()
        except (requests.RequestException, OSError):
            # Interrupted headers/body can surface as EOF, protocol or SSL errors.
            # Preserve cancellation vs ordinary failure for resumable scanners.
            deadline.check()
            raise
        finally:
            if response is not None:
                response.close()
        response._content, response._content_consumed = bytes(body), True
        return response
