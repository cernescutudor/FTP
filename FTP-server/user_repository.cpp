#include "user_repository.h"

UserRepository::UserRepository()
{

    users["admin"] = "1234";
    users["user"] = "password";
}

bool UserRepository::validate_user(const std::string &username, const std::string &password)
{
    auto it = users.find(username);
    if (it != users.end() && it->second == password)
    {
        return true; 
    }
    return false; 
}

bool UserRepository::validate_user(const std::string &username)
{
    return users.find(username) != users.end();
}
