// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <filesystem>
#include <stdexcept>
#include <string>

namespace bseal {

class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};

class NotImplemented final : public Error {
public:
    explicit NotImplemented(const std::string& area)
        : Error(area + " is not implemented in the BSEAL skeleton") {}
};

class InvalidArgument final : public Error {
public:
    explicit InvalidArgument(const std::string& message) : Error(message) {}
};

class AuthenticationFailed final : public Error {
public:
    explicit AuthenticationFailed() : Error("authentication failed or archive is corrupt") {}
};

class SystemError final : public Error {
public:
    explicit SystemError(const std::string& message) : Error(message) {}
};

// Thrown when a keyfile cannot be read or does not exist.
// Stores the path separately so GUI layers can show only the basename,
// preventing full directory paths from appearing in user-visible messages.
class KeyfileAccessError final : public Error {
public:
    KeyfileAccessError(const std::string& description, const std::filesystem::path& path)
        : Error(description + ": " + path.string()), path_(path) {}

    [[nodiscard]] const std::filesystem::path& keyfile_path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

} // namespace bseal
