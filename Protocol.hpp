// Protocol.hpp
#pragma once
#include <string>

// Interface for protocols
class IProtocol{
public:
    virtual ~IProtocol() = default;
    virtual std::string processIncoming(const std::string& data) = 0;
    virtual std::string prepareOutgoing(const std::string& data) = 0;
};

// protocol skeleton
