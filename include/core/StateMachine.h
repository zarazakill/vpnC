#pragma once
#include <functional>
#include <map>
#include <string>
#include <mutex>

class StateMachine {
public:
    using StateHandler = std::function<void()>;
    using TransitionCallback = std::function<void(const std::string&,
                                                  const std::string&)>;

                                                  StateMachine();

                                                  void addState(const std::string& state, StateHandler entry_handler = nullptr,
                                                                StateHandler exit_handler = nullptr);
                                                  void addTransition(const std::string& from, const std::string& to,
                                                                     const std::string& event, StateHandler handler = nullptr);

                                                  bool transition(const std::string& event);
                                                  void setTransitionCallback(TransitionCallback callback);

                                                  const std::string& getCurrentState() const { return current_state_; }
                                                  bool isState(const std::string& state) const { return current_state_ == state; }

private:
    struct StateInfo {
        StateHandler on_entry;
        StateHandler on_exit;
    };

    struct Transition {
        std::string from_state;
        std::string to_state;
        StateHandler handler;
    };

    std::string current_state_;
    std::map<std::string, StateInfo> states_;
    std::multimap<std::string, Transition> transitions_;
    TransitionCallback transition_callback_;
    std::mutex mutex_;

    bool isValidTransition(const std::string& from,
                           const std::string& to,
                           const std::string& event) const;
};
