
#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    // 1. Create a TCP socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (clientSocket == -1) {
        perror("socket");
        return 1;
    }

    // 2. Configure the server address
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);

    if (inet_pton(AF_INET, "127.0.0.1",
                  &serverAddress.sin_addr) != 1) {
        std::cerr << "Invalid server IP address.\n";
        close(clientSocket);
        return 1;
    }

    // 3. Connect to the server
    if (connect(clientSocket,
                reinterpret_cast<sockaddr*>(&serverAddress),
                sizeof(serverAddress)) == -1) {
        perror("connect");
        close(clientSocket);
        return 1;
    }

    std::cout << "Connected to server!\n";

    // 4. Send a message
    std::string message = "Hello from client!";

    ssize_t bytesSent = send(
        clientSocket, message.data(), message.size(), 0);

    if (bytesSent == -1) {
        perror("send");
        close(clientSocket);
        return 1;
    }

    // 5. Receive the server reply
    char buffer[1024]{};

    ssize_t bytesReceived = recv(
        clientSocket, buffer, sizeof(buffer) - 1, 0);

    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        std::cout << "Server says: " << buffer << '\n';
    } else if (bytesReceived == 0) {
        std::cout << "Server closed the connection.\n";
    } else {
        perror("recv");
    }

    // 6. Close the socket
    close(clientSocket);

    return 0;
}
