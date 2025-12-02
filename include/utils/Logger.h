#pragma once
#include <string>
#include <fstream>
#include <memory>
#include <mutex>
#include <functional>
#include <vector>

class Logger {
public:
    enum class LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    };

    static Logger& getInstance();

    void setLogFile(const std::string& filename);
    void setLogLevel(LogLevel level);
    void setConsoleOutput(bool enable);

    void log(LogLevel level, const std::string& message,
             const std::string& component = "");

    void addCallback(std::function<void(LogLevel, const std::string&,
                                        const std::string&)> callback);

private:
    Logger();
    ~Logger();

    std::ofstream log_file_;
    LogLevel current_level_;
    bool console_output_;
    std::mutex mutex_;
    std::vector<std::function<void(LogLevel, const std::string&,
                                   const std::string&)>> callbacks_;

                                   std::string levelToString(LogLevel level) const;
                                   std::string getTimestamp() const;
                                   bool shouldLog(LogLevel level) const;
};
