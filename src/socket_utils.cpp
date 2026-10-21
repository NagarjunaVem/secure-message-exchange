// Author: Vem Nagarjuna Reddy
// Roll Number: 20243315
// Purpose: Open, use, and close TCP sockets on Windows and POSIX systems.

#include "socket_utils.h"

#include <cerrno>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

#ifdef _WIN32
#include <climits>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

using namespace std;

namespace socket_utils {
namespace {

string socketError(const string& operation) {
#ifdef _WIN32
    return operation + " failed with Winsock error " + to_string(WSAGetLastError());
#else
    return operation + " failed: " + strerror(errno);
#endif
}

void closeSocket(SocketHandle handle) noexcept {
    if (handle == INVALID_SOCKET_HANDLE) {
        return;
    }
#ifdef _WIN32
    closesocket(handle);
#else
    close(handle);
#endif
}

}  // namespace

SocketRuntime::SocketRuntime() {
#ifdef _WIN32
    WSADATA data{};
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        throw runtime_error("WSAStartup failed with Winsock error " + to_string(result));
    }
    initialized_ = true;
#endif
}

SocketRuntime::~SocketRuntime() {
#ifdef _WIN32
    if (initialized_) {
        WSACleanup();
    }
#endif
}

TcpSocket::TcpSocket(SocketHandle handle) : handle_(handle) {}

TcpSocket::~TcpSocket() {
    closeSocket(handle_);
}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept : handle_(other.handle_) {
    other.handle_ = INVALID_SOCKET_HANDLE;
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        closeSocket(handle_);
        handle_ = other.handle_;
        other.handle_ = INVALID_SOCKET_HANDLE;
    }
    return *this;
}

TcpSocket TcpSocket::connectTo(const string& host, uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Find an address for the server name, then try each returned address.
    addrinfo* addresses = nullptr;
    const string service = to_string(port);
    const int lookup = getaddrinfo(host.c_str(), service.c_str(), &hints, &addresses);
    if (lookup != 0) {
#ifdef _WIN32
        throw runtime_error("getaddrinfo failed with Winsock error " + to_string(lookup));
#else
        throw runtime_error(string("getaddrinfo failed: ") + gai_strerror(lookup));
#endif
    }

    SocketHandle connected = INVALID_SOCKET_HANDLE;
    for (addrinfo* address = addresses; address != nullptr; address = address->ai_next) {
        const SocketHandle candidate = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (candidate == INVALID_SOCKET_HANDLE) {
            continue;
        }
#ifdef _WIN32
        const int result = connect(candidate, address->ai_addr, static_cast<int>(address->ai_addrlen));
        const bool succeeded = result != SOCKET_ERROR;
#else
        const int result = connect(candidate, address->ai_addr, static_cast<socklen_t>(address->ai_addrlen));
        const bool succeeded = result == 0;
#endif
        if (succeeded) {
            connected = candidate;
            break;
        }
        closeSocket(candidate);
    }
    freeaddrinfo(addresses);

    if (connected == INVALID_SOCKET_HANDLE) {
        throw runtime_error(socketError("connect"));
    }
    return TcpSocket(connected);
}

TcpSocket TcpSocket::listenOn(uint16_t port) {
    addrinfo hints{};
    // Keep the server address compatible with the default IPv4 client address.
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Bind the listening socket to the requested local port.
    addrinfo* addresses = nullptr;
    const string service = to_string(port);
    const int lookup = getaddrinfo(nullptr, service.c_str(), &hints, &addresses);
    if (lookup != 0) {
#ifdef _WIN32
        throw runtime_error("getaddrinfo failed with Winsock error " + to_string(lookup));
#else
        throw runtime_error(string("getaddrinfo failed: ") + gai_strerror(lookup));
#endif
    }

    SocketHandle listener = INVALID_SOCKET_HANDLE;
    for (addrinfo* address = addresses; address != nullptr; address = address->ai_next) {
        const SocketHandle candidate = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (candidate == INVALID_SOCKET_HANDLE) {
            continue;
        }

        const int reuseAddress = 1;
#ifdef _WIN32
        setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuseAddress), sizeof(reuseAddress));
        const int bindResult = bind(candidate, address->ai_addr, static_cast<int>(address->ai_addrlen));
#else
        setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR, &reuseAddress, sizeof(reuseAddress));
        const int bindResult = bind(candidate, address->ai_addr, static_cast<socklen_t>(address->ai_addrlen));
#endif
        if (bindResult == 0 && listen(candidate, SOMAXCONN) == 0) {
            listener = candidate;
            break;
        }
        closeSocket(candidate);
    }
    freeaddrinfo(addresses);

    if (listener == INVALID_SOCKET_HANDLE) {
        throw runtime_error(socketError("bind/listen"));
    }
    return TcpSocket(listener);
}

TcpSocket TcpSocket::acceptOne() const {
    if (!isOpen()) {
        throw runtime_error("Cannot accept on a closed socket");
    }
    sockaddr_storage address{};
#ifdef _WIN32
    int addressLength = sizeof(address);
#else
    socklen_t addressLength = sizeof(address);
#endif
    const SocketHandle accepted = accept(handle_, reinterpret_cast<sockaddr*>(&address), &addressLength);
    if (accepted == INVALID_SOCKET_HANDLE) {
        throw runtime_error(socketError("accept"));
    }
    return TcpSocket(accepted);
}

void TcpSocket::sendAll(const uint8_t* data, size_t size) const {
    if (!isOpen()) {
        throw runtime_error("Cannot send on a closed socket");
    }
    size_t sent = 0;
    while (sent < size) {
#ifdef _WIN32
        const int chunk = static_cast<int>(size - sent > static_cast<size_t>(INT_MAX) ? INT_MAX : size - sent);
        const int count = ::send(handle_, reinterpret_cast<const char*>(data + sent), chunk, 0);
        if (count == SOCKET_ERROR) {
            throw runtime_error(socketError("send"));
        }
#else
        const ssize_t count = ::send(handle_, data + sent, size - sent, 0);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw runtime_error(socketError("send"));
        }
#endif
        if (count == 0) {
            throw runtime_error("Socket closed while sending");
        }
        sent += static_cast<size_t>(count);
    }
}

void TcpSocket::receiveAll(uint8_t* data, size_t size) const {
    if (!isOpen()) {
        throw runtime_error("Cannot receive on a closed socket");
    }
    size_t received = 0;
    while (received < size) {
#ifdef _WIN32
        const int chunk = static_cast<int>(size - received > static_cast<size_t>(INT_MAX) ? INT_MAX : size - received);
        const int count = ::recv(handle_, reinterpret_cast<char*>(data + received), chunk, 0);
        if (count == SOCKET_ERROR) {
            throw runtime_error(socketError("recv"));
        }
#else
        const ssize_t count = ::recv(handle_, data + received, size - received, 0);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw runtime_error(socketError("recv"));
        }
#endif
        if (count == 0) {
            throw runtime_error("Peer closed the connection");
        }
        received += static_cast<size_t>(count);
    }
}

bool TcpSocket::isOpen() const {
    return handle_ != INVALID_SOCKET_HANDLE;
}

void sendFrame(const TcpSocket& socket, const uint8_t* data, size_t size) {
    if (size > numeric_limits<uint32_t>::max()) {
        throw length_error("Frame exceeds the 32-bit length field");
    }
    // Send the frame size first so the receiver knows how many bytes to read.
    const uint32_t length = static_cast<uint32_t>(size);
    const uint8_t prefix[] = {static_cast<uint8_t>(length >> 24U), static_cast<uint8_t>(length >> 16U), static_cast<uint8_t>(length >> 8U), static_cast<uint8_t>(length)};
    socket.sendAll(prefix, sizeof(prefix));
    socket.sendAll(data, size);
}

vector<uint8_t> receiveFrame(const TcpSocket& socket, size_t maximumSize) {
    uint8_t prefix[4]{};
    socket.receiveAll(prefix, sizeof(prefix));
    const uint32_t length = (static_cast<uint32_t>(prefix[0]) << 24U) | (static_cast<uint32_t>(prefix[1]) << 16U) | (static_cast<uint32_t>(prefix[2]) << 8U) | static_cast<uint32_t>(prefix[3]);
    if (length > maximumSize) {
        throw length_error("Received frame exceeds the configured limit");
    }
    vector<uint8_t> frame(length);
    if (length != 0) {
        socket.receiveAll(frame.data(), length);
    }
    return frame;
}

}  // namespace socket_utils
