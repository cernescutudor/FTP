#ifndef USER_REPOSITORY_H
#define USER_REPOSITORY_H

#include <string>
#include <unordered_map>

class UserRepository {
public:
    UserRepository();
    bool validate_user(const std::string &username, const std::string &password);
    bool validate_user(const std::string &username);

private:
    std::unordered_map<std::string, std::string> users; // Mapare username -> password
};

#endif // USER_REPOSITORY_H
