#include "reconnection_manager.h"
#include <iostream>

ReconnectionManager::ReconnectionManager(int interval, int max_attempts)
    : running_(false), reconnect_interval_(interval), max_reconnect_attempts_(max_attempts) {}

ReconnectionManager::~ReconnectionManager() {
    stop();
}

void ReconnectionManager::start(std::function<bool()> check_func, std::function<void()> reconnect_func) {
    if (running_) {
        stop();
    }
    
    connection_check_func_ = check_func;
    reconnect_func_ = reconnect_func;
    running_ = true;
    
    reconnection_thread_ = std::thread(&ReconnectionManager::reconnectionLoop, this);
}

void ReconnectionManager::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    if (reconnection_thread_.joinable()) {
        reconnection_thread_.join();
    }
}

void ReconnectionManager::reconnectionLoop() {
    int failed_attempts = 0;
    
    while (running_) {
        // Проверяем соединение
        if (!connection_check_func_()) {
            std::cout << "Обнаружено отключение от сервера" << std::endl;
            failed_attempts++;
            
            if (failed_attempts <= max_reconnect_attempts_) {
                std::cout << "Попытка переподключения... (попытка " << failed_attempts << ")" << std::endl;
                
                // Выполняем переподключение
                reconnect_func_();
                
                // Ждем перед следующей попыткой
                std::this_thread::sleep_for(std::chrono::seconds(reconnect_interval_));
            } else {
                std::cout << "Достигнуто максимальное количество попыток переподключения" << std::endl;
                break;
            }
        } else {
            // Соединение активно, сбрасываем счётчик неудач
            failed_attempts = 0;
        }
        
        // Ждем перед следующей проверкой
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}