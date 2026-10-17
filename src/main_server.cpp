
#include <iostream>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    // 1. Create the server socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket == -1) {
        perror("socket");
        return 1;
    }

    // Allow quick reuse of the port during development
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR,
                   &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        close(serverSocket);
        return 1;
    }

    // 2. Configure the server address
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    // 3. Bind the socket to port 8080
    if (bind(serverSocket,
             reinterpret_cast<sockaddr*>(&serverAddress),
             sizeof(serverAddress)) == -1) {
        perror("bind");
        close(serverSocket);
        return 1;
    }

    // 4. Start listening for connections
    if (listen(serverSocket, 5) == -1) {
        perror("listen");
        close(serverSocket);
        return 1;
    }

    std::cout << "Server listening on port 8080...\n";

    // 5. Accept one client connection
    sockaddr_in clientAddress{};
    socklen_t clientLength = sizeof(clientAddress);

    int clientSocket = accept(
        serverSocket,
        reinterpret_cast<sockaddr*>(&clientAddress),
        &clientLength);

    if (clientSocket == -1) {
        perror("accept");
        close(serverSocket);
        return 1;
    }

    std::cout << "Client connected!\n";

    // 6. Receive a message
    char buffer[1024]{};

    ssize_t bytesReceived = recv(
        clientSocket, buffer, sizeof(buffer) - 1, 0);

    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';

        std::cout << "Client says: " << buffer << '\n';

        // 7. Send a reply
        std::string reply = "Hello from server!";

        ssize_t bytesSent = send(
            clientSocket, reply.data(), reply.size(), 0);

        if (bytesSent == -1) {
            perror("send");
        }
    } else if (bytesReceived == 0) {
        std::cout << "Client disconnected without sending data.\n";
    } else {
        perror("recv");
    }

    // 8. Close the connected socket and listening socket
    close(clientSocket);
    close(serverSocket);

    std::cout << "Server stopped.\n";
    return 0;
}
