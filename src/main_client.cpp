
#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

int main() {
    // 1. Create socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    // 2. Set server address and port
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);

    // 3. Connect to server
    connect(clientSocket, (sockaddr*)&serverAddress, sizeof(serverAddress));

    cout << "Connected to server!\n";

    // 4. Send message
    string message = "Hello from client!";
    send(clientSocket, message.c_str(), message.size(), 0);

    // 5. Receive reply
    char buffer[1024] = {};
    int n = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

    if (n > 0) {
        buffer[n] = '\0';
        cout << "Server says: " << buffer << endl;
    }

    // 6. Close socket
    close(clientSocket);

    return 0;
}
