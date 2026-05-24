#pragma once

#include <stdexcept>
#include <string>

namespace bseal {

    class Error : public std::runtime_error {
      public:
        explicit Error(const std::string &message) : std::runtime_error(message) {}
    };

    class NotImplemented final : public Error {
      public:
        explicit NotImplemented(const std::string &area)
            : Error(area + " is not implemented in the BSEAL skeleton") {}
    };

    class InvalidArgument final : public Error {
      public:
        explicit InvalidArgument(const std::string &message) : Error(message) {}
    };

    class AuthenticationFailed final : public Error {
      public:
        explicit AuthenticationFailed() : Error("authentication failed or archive is corrupt") {}
    };

    class SystemError final : public Error {
      public:
        explicit SystemError(const std::string &message) : Error(message) {}
    };

} // namespace bseal
