
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace std;

int main() {
    // 1. Create socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    // 2. Set server address and port
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // 3. Bind socket
    bind(serverSocket, (sockaddr*)&serverAddress, sizeof(serverAddress));

    // 4. Listen for client
    listen(serverSocket, 5);
    cout << "Server waiting for client...\n";

    // 5. Accept client connection
    int clientSocket = accept(serverSocket, nullptr, nullptr);
    cout << "Client connected!\n";

    // 6. Receive message
    char buffer[1024] = {};
    int n = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

    if (n > 0) {
        buffer[n] = '\0';
        cout << "Client says: " << buffer << endl;

        // 7. Send reply
        string reply = "Hello from server!";
        send(clientSocket, reply.c_str(), reply.size(), 0);
    }

    // 8. Close sockets
    close(clientSocket);
    close(serverSocket);

    return 0;
}
