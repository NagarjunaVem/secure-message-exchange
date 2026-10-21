#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

namespace socket_utils {

#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle INVALID_SOCKET_HANDLE = INVALID_SOCKET;
#else
using SocketHandle = int;
constexpr SocketHandle INVALID_SOCKET_HANDLE = -1;
#endif

class SocketRuntime {
   public:
    SocketRuntime();
    ~SocketRuntime();

    SocketRuntime(const SocketRuntime&) = delete;
    SocketRuntime& operator=(const SocketRuntime&) = delete;

   private:
    bool initialized_ = false;
};

class TcpSocket {
   public:
    TcpSocket() = default;
    explicit TcpSocket(SocketHandle handle);
    ~TcpSocket();

    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    TcpSocket(TcpSocket&& other) noexcept;
    TcpSocket& operator=(TcpSocket&& other) noexcept;

    static TcpSocket connectTo(const std::string& host, std::uint16_t port);
    static TcpSocket listenOn(std::uint16_t port);

    TcpSocket acceptOne() const;
    void sendAll(const std::uint8_t* data, std::size_t size) const;
    void receiveAll(std::uint8_t* data, std::size_t size) const;
    bool isOpen() const;

   private:
    SocketHandle handle_ = INVALID_SOCKET_HANDLE;
};

void sendFrame(const TcpSocket& socket, const std::uint8_t* data, std::size_t size);
std::vector<std::uint8_t> receiveFrame(const TcpSocket& socket, std::size_t maximumSize = 16U * 1024U * 1024U);

}  // namespace socket_utils

#endif
