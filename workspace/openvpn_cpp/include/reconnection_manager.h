#ifndef RECONNECTION_MANAGER_H
#define RECONNECTION_MANAGER_H

#include <atomic>
#include <thread>
#include <functional>

class ReconnectionManager {
private:
    std::atomic<bool> running_;
    std::thread reconnection_thread_;
    int reconnect_interval_;
    int max_reconnect_attempts_;
    std::function<bool()> connection_check_func_;
    std::function<void()> reconnect_func_;
    
public:
    ReconnectionManager(int interval = 5, int max_attempts = 10);
    ~ReconnectionManager();
    
    void start(std::function<bool()> check_func, std::function<void()> reconnect_func);
    void stop();
    void setReconnectInterval(int interval) { reconnect_interval_ = interval; }
    void setMaxReconnectAttempts(int attempts) { max_reconnect_attempts_ = attempts; }
    
private:
    void reconnectionLoop();
};

#endif // RECONNECTION_MANAGER_H