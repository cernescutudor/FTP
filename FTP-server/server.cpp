#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <string>
#include <dirent.h>
#include <sys/types.h>
#include <fstream>
#include <filesystem>
#include <regex>
#include <sys/stat.h>
#include <limits.h>

#include "user_repository.h"

#define PORT 2121
#define BUFFER_SIZE 1024

constexpr const char *BASE_PATH = "./ServerResources";

void handle_client(int client_socket);
void list_directory(int client_socket, int data_socket, const std::string &relative_path = "");
void send_file_to_client(int client_socket, int data_socket, const std::string &relative_path);
void receive_file_from_client(int client_socket, int data_socket, const std::string &relative_path);
std::string construct_safe_path(const std::string &relative_path);
int setup_active_data_connection(const std::string &client_ip, int client_port);
int setup_passive_data_connection(int control_socket);
void NLST(int client_socket, int data_socket, const std::string &relative_path = "");

int main()
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        perror("Eroare la creare socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Eroare la bind");
        close(server_socket);
        return 1;
    }

    if (listen(server_socket, 5) < 0)
    {
        perror("Eroare la listen");
        close(server_socket);
        return 1;
    }

    std::cout << "Serverul FTP rulează pe portul " << PORT << "...\n";

    while (true)
    {

        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0)
        {
            perror("Eroare la accept");
            continue;
        }

        std::cout << "Client conectat: " << inet_ntoa(client_addr.sin_addr) << "\n";
        handle_client(client_socket);
        close(client_socket);
    }

    close(server_socket);
    return 0;
}

void handle_client(int client_socket)
{
    char buffer[BUFFER_SIZE] = {0};
    std::string current_user;
    bool authenticated = false;
    bool passive_mode = false;
    int data_socket = -1;
    int passive_socket = -1;
    std::string client_ip;
    int client_port;

    UserRepository user_repo;

    const char *welcome_msg = "220 Bun venit la serverul FTP\r\n";
    send(client_socket, welcome_msg, strlen(welcome_msg), 0);

    while (true)
    {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0)
        {
            std::cout << "Client deconectat.\n";
            break;
        }

        std::cout << "Comandă primită: " << buffer;

        if (strncmp(buffer, "USER", 4) == 0)
        {

            char username[BUFFER_SIZE] = {0};
            sscanf(buffer, "USER %s", username);
            if (user_repo.validate_user(username))
            {
                current_user = username;
                const char *user_response = "331 Username OK, aștept parola\r\n";
                send(client_socket, user_response, strlen(user_response), 0);
            }
            else
            {
                const char *user_response = "530 Utilizator inexistent\r\n";
                send(client_socket, user_response, strlen(user_response), 0);
            }
        }
        else if (strncmp(buffer, "PASS", 4) == 0)
        {

            char password[BUFFER_SIZE] = {0};
            sscanf(buffer, "PASS %s", password);

            if (user_repo.validate_user(current_user, password))
            {
                authenticated = true;
                const char *pass_response = "230 Utilizator autentificat cu succes\r\n";
                send(client_socket, pass_response, strlen(pass_response), 0);
            }
            else
            {
                const char *pass_response = "530 Autentificare eșuată\r\n";
                send(client_socket, pass_response, strlen(pass_response), 0);
            }
        }
        else if (strncmp(buffer, "QUIT", 4) == 0)
        {
            const char *quit_response = "221 Goodbye.\r\n";
            send(client_socket, quit_response, strlen(quit_response), 0);
            break;
        }
        else if (!authenticated)
        {
            const char *auth_required = "530 Trebuie să fiți autentificat\r\n";
            send(client_socket, auth_required, strlen(auth_required), 0);
        }
        else if (strncmp(buffer, "PORT", 4) == 0)
        {
            int client_ip1, client_ip2, client_ip3, client_ip4, p1, p2;
            sscanf(buffer, "PORT %d,%d,%d,%d,%d,%d", &client_ip1, &client_ip2, &client_ip3, &client_ip4, &p1, &p2);
            client_ip = std::to_string(client_ip1) + "." + std::to_string(client_ip2) + "." + std::to_string(client_ip3) + "." + std::to_string(client_ip4);
            client_port = p1 * 256 + p2;
            passive_mode = false;
            const char *port_response = "200 PORT command successful.\r\n";
            send(client_socket, port_response, strlen(port_response), 0);
        }
        else if (strncmp(buffer, "PASV", 4) == 0)
        {
            passive_mode = true;
            passive_socket = setup_passive_data_connection(client_socket);
            if (passive_socket < 0)
            {
                const char *error_msg = "425 Can't open data connection.\r\n";
                send(client_socket, error_msg, strlen(error_msg), 0);
            }
        }
        else if (strncmp(buffer, "LIST", 4) == 0)
        {
            if (passive_mode)
            {
                data_socket = accept(passive_socket, NULL, NULL);
                if (data_socket < 0)
                {
                    perror("Eroare la accept pe socketul pasiv");
                }
                close(passive_socket);
            }
            else
            {
                data_socket = setup_active_data_connection(client_ip, client_port);
            }
            char path[BUFFER_SIZE] = {0};
            if (sscanf(buffer, "LIST %s", path) == 1)
            {
                NLST(client_socket, data_socket, path);
            }
            else
            {
                NLST(client_socket, data_socket);
            }
            close(data_socket);
        }
        else if (strncmp(buffer, "NLST", 4) == 0)
        {
            if (passive_mode)
            {
                data_socket = accept(passive_socket, NULL, NULL);
                if (data_socket < 0)
                {
                    perror("Eroare la accept pe socketul pasiv");
                }
                close(passive_socket);
            }
            else
            {
                data_socket = setup_active_data_connection(client_ip, client_port);
            }
            char path[BUFFER_SIZE] = {0};
            if (sscanf(buffer, "NLST %s", path) == 1)
            {
                NLST(client_socket, data_socket, path);
            }
            else
            {
                NLST(client_socket, data_socket);
            }
            close(data_socket);
        }
        else if (strncmp(buffer, "RETR", 4) == 0)
        {
            if (passive_mode)
            {
                data_socket = accept(passive_socket, NULL, NULL);
                close(passive_socket);
            }
            else
            {
                data_socket = setup_active_data_connection(client_ip, client_port);
            }
            char filename[BUFFER_SIZE] = {0};
            sscanf(buffer, "RETR %s", filename);
            send_file_to_client(client_socket, data_socket, filename);
            close(data_socket);
        }
        else if (strncmp(buffer, "STOR", 4) == 0)
        {
            if (passive_mode)
            {
                data_socket = accept(passive_socket, NULL, NULL);
                close(passive_socket);
            }
            else
            {
                data_socket = setup_active_data_connection(client_ip, client_port);
            }
            char filename[BUFFER_SIZE] = {0};
            sscanf(buffer, "STOR %s", filename);
            receive_file_from_client(client_socket, data_socket, filename);
            close(data_socket);
        }
        else
        {
            const char *unknown_command = "502 Comandă necunoscută\r\n";
            send(client_socket, unknown_command, strlen(unknown_command), 0);
        }
    }
}

int setup_active_data_connection(const std::string &client_ip, int client_port)
{
    int data_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (data_socket < 0)
    {
        perror("Eroare la creare socket de date");
        return -1;
    }

    struct sockaddr_in data_addr;
    memset(&data_addr, 0, sizeof(data_addr));
    data_addr.sin_family = AF_INET;
    data_addr.sin_port = htons(client_port);

    if (inet_pton(AF_INET, client_ip.c_str(), &data_addr.sin_addr) != 1)
    {
        std::cerr << "Eroare la inet_pton: Adresa IP invalidă (" << client_ip << ")\n";
        close(data_socket);
        return -1;
    }

    if (connect(data_socket, (struct sockaddr *)&data_addr, sizeof(data_addr)) < 0)
    {
        perror("Eroare la conectare");
        close(data_socket);
        return -1;
    }

    return data_socket;
}

int setup_passive_data_connection(int control_socket)
{
    int passive_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (passive_socket < 0)
    {
        perror("Eroare la creare socket pasiv");
        return -1;
    }

    struct sockaddr_in passive_addr;
    memset(&passive_addr, 0, sizeof(passive_addr));
    passive_addr.sin_family = AF_INET;
    passive_addr.sin_addr.s_addr = INADDR_ANY;
    passive_addr.sin_port = 0;

    if (bind(passive_socket, (struct sockaddr *)&passive_addr, sizeof(passive_addr)) < 0)
    {
        perror("Eroare la bind pe socketul pasiv");
        close(passive_socket);
        return -1;
    }

    socklen_t len = sizeof(passive_addr);
    if (getsockname(passive_socket, (struct sockaddr *)&passive_addr, &len) < 0)
    {
        perror("Eroare la getsockname");
        close(passive_socket);
        return -1;
    }

    if (listen(passive_socket, 1) < 0)
    {
        perror("Eroare la listen pe socketul pasiv");
        close(passive_socket);
        return -1;
    }

    int passive_port = ntohs(passive_addr.sin_port);
    std::string server_ip = "127,0,0,1";

    char pasv_response[BUFFER_SIZE];
    snprintf(pasv_response, sizeof(pasv_response), "227 Entering Passive Mode (%s,%d,%d).\r\n", server_ip.c_str(), passive_port / 256, passive_port % 256);
    send(control_socket, pasv_response, strlen(pasv_response), 0);

    return passive_socket;
}

std::string construct_safe_path(const std::string &relative_path)
{
    try
    {
        std::filesystem::path base_path = std::filesystem::canonical(BASE_PATH);

        std::filesystem::path requested_path = base_path / relative_path;
        // std::cout << "Requested path: " << requested_path << std::endl;

        requested_path = std::filesystem::canonical(requested_path);

        if (requested_path.string().find(base_path.string()) != 0)
        {
            throw std::runtime_error("Unauthorized access attempt detected.");
        }

        return requested_path.string();
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error("Invalid path.");
    }
}

void receive_file_from_client(int client_socket, int data_socket, const std::string &relative_path)
{
    try
    {
        std::filesystem::path base_path = std::filesystem::canonical(BASE_PATH);
        std::filesystem::path requested_path = base_path / relative_path;
        requested_path = std::filesystem::weakly_canonical(requested_path);
        // std::cout << "Requested path: " << requested_path << std::endl;

        if (requested_path.string().find(base_path.string()) != 0)
        {
            throw std::runtime_error("Unauthorized access attempt detected.");
        }

        FILE *file = fopen(requested_path.c_str(), "wb");
        if (!file)
        {
            throw std::runtime_error("Error creating file.");
        }

        const char *start_msg = "150 Ready to receive data\r\n";
        send(client_socket, start_msg, strlen(start_msg), 0);

        char buffer[BUFFER_SIZE] = {0};
        int bytes_received;
        while ((bytes_received = recv(data_socket, buffer, sizeof(buffer), 0)) > 0)
        {
            fwrite(buffer, 1, bytes_received, file);
        }
        fclose(file);

        const char *end_msg = "226 Transfer complete\r\n";
        send(client_socket, end_msg, strlen(end_msg), 0);
    }
    catch (const std::exception &e)
    {
        std::cout << e.what() << std::endl;
        const char *error_msg = "550 Failed to receive file\r\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
    }
}

void send_file_to_client(int client_socket, int data_socket, const std::string &relative_path)
{
    try
    {
        std::string full_path = construct_safe_path(relative_path);

        if (!std::filesystem::is_regular_file(full_path))
        {
            throw std::runtime_error("Invalid or non-existent file.");
        }

        FILE *file = fopen(full_path.c_str(), "rb");
        if (!file)
        {
            throw std::runtime_error("Error opening file.");
        }

        const char *start_msg = "150 Opening data connection\r\n";
        send(client_socket, start_msg, strlen(start_msg), 0);

        char buffer[BUFFER_SIZE] = {0};
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
        {
            send(data_socket, buffer, bytes_read, 0);
        }
        fclose(file);

        const char *end_msg = "226 Transfer complete\r\n";
        send(client_socket, end_msg, strlen(end_msg), 0);
    }
    catch (const std::exception &e)
    {
        const char *error_msg = "550 Requested action not taken. File unavailable\r\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
    }
}

void list_directory(int client_socket, int data_socket, const std::string &relative_path) // Echivalentul la ls -l
{
    char buffer[BUFFER_SIZE] = {0};

    try
    {
        std::string full_path = construct_safe_path(relative_path);

        DIR *dir = opendir(full_path.c_str());
        if (!dir)
        {
            perror("opendir");
            send(client_socket, "550 Failed to open directory.\r\n", 32, 0);
            return;
        }

        struct dirent *entry;
        struct stat file_stat;
        char file_path[PATH_MAX];
        char buffer[BUFFER_SIZE];
        std::string listing;

        while ((entry = readdir(dir)) != NULL)
        {
            // Skip `.` and `..`
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            // Build the full path for the current entry
            snprintf(file_path, sizeof(file_path), "%s/%s", full_path.c_str(), entry->d_name);

            // Perform stat on the entry
            if (stat(file_path, &file_stat) != 0)
            {
                perror("stat");
                continue;
            }

            // Determine file type and permissions
            char permissions[11];
            snprintf(permissions, sizeof(permissions), "%c%c%c%c%c%c%c%c%c%c",
                     S_ISDIR(file_stat.st_mode) ? 'd' : '-',
                     (file_stat.st_mode & S_IRUSR) ? 'r' : '-',
                     (file_stat.st_mode & S_IWUSR) ? 'w' : '-',
                     (file_stat.st_mode & S_IXUSR) ? 'x' : '-',
                     (file_stat.st_mode & S_IRGRP) ? 'r' : '-',
                     (file_stat.st_mode & S_IWGRP) ? 'w' : '-',
                     (file_stat.st_mode & S_IXGRP) ? 'x' : '-',
                     (file_stat.st_mode & S_IROTH) ? 'r' : '-',
                     (file_stat.st_mode & S_IWOTH) ? 'w' : '-',
                     (file_stat.st_mode & S_IXOTH) ? 'x' : '-');

            // Get modification time
            char time_buffer[20];
            struct tm *tm_info = localtime(&file_stat.st_mtime);
            strftime(time_buffer, sizeof(time_buffer), "%b %d %H:%M", tm_info);

            // Format listing entry
            snprintf(buffer, BUFFER_SIZE, "%s %ld %ld %ld %ld %s %s\r\n",
                     permissions,              // Permissions
                     (long)file_stat.st_nlink, // Number of links
                     (long)file_stat.st_uid,   // User ID of owner
                     (long)file_stat.st_gid,   // Group ID of owner
                     (long)file_stat.st_size,  // File size in bytes
                     time_buffer,              // Last modified time
                     entry->d_name);           // File name

            // Append to listing
            listing += buffer;
        }

        closedir(dir);


        if (send(data_socket, listing.c_str(), listing.size(), 0) < 0)
        {
            perror("send");
            send(client_socket, "450 Failed to send directory listing.\r\n", 40, 0);
            return;
        }


        close(data_socket);
        send(client_socket, "226 Directory listing completed.\r\n", 35, 0);
    }
    catch (const std::exception &e)
    {
        const char *error_msg = "550 Invalid path\r\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
    }
}

void NLST(int client_socket, int data_socket, const std::string &relative_path)
{
    try
    {
        DIR *dir;
        struct dirent *entry;
        std::string listing;
        std::string directory_path = construct_safe_path(relative_path);
        // Open the directory
        dir = opendir(directory_path.c_str());
        if (dir == NULL)
        {
            std::cerr << "Failed to open directory: " << directory_path << std::endl;
            send(client_socket, "550 Failed to open directory.\r\n", 32, 0);
            return;
        }

        // Read each entry in the directory
        while ((entry = readdir(dir)) != NULL)
        {
            // Skip `.` and `..`
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            // Append the file or directory name followed by CRLF
            listing += entry->d_name;
            listing += "\r\n";
        }
        std::cout << "Here";

        // Close the directory
        closedir(dir);

        // Send 150 response to indicate data transfer start
        send(client_socket, "150 Opening data connection for LIST.\r\n", 41, 0);

        // Send the listing to the client over the data socket
        if (send(data_socket, listing.c_str(), listing.size(), 0) < 0)
        {
            std::cerr << "Error sending directory listing.\n";
        }

        // Send 226 response to indicate successful transfer
        send(client_socket, "226 Transfer complete.\r\n", 26, 0);

        // Close the data connection
        close(data_socket);
    }
    catch (const std::exception &e)
    {
        const char *error_msg = "550 Invalid path\r\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
    }
}