#ifndef AUTHENTICATION_MANAGER_H
#define AUTHENTICATION_MANAGER_H

#include <string>

class AuthenticationManager {
private:
    std::string username;
    std::string password;
    std::string token;
    
public:
    AuthenticationManager(const std::string& user, const std::string& pass);
    
    bool authenticate();
    const std::string& getUsername() const { return username; }
    const std::string& getPassword() const { return password; }
    const std::string& getToken() const { return token; }
    
private:
    void generateToken();
};

#endif // AUTHENTICATION_MANAGER_H