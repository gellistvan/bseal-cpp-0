#include "archive/PathSanitizer.hpp"

#include "common/Errors.hpp"

#include <cctype>

namespace bseal::archive {

bool is_safe_relative_path(const std::filesystem::path& path) {
    if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory()) {
        return false;
    }

    // Reject Windows drive letters ("C:/", "C:\") and UNC backslash paths ("\\server\share")
    // that std::filesystem does not parse as absolute on POSIX.
    const auto str = path.generic_string();
    if (str.size() >= 2) {
        const unsigned char c0 = static_cast<unsigned char>(str[0]);
        const unsigned char c1 = static_cast<unsigned char>(str[1]);
        if ((std::isalpha(c0) && c1 == ':') || (c0 == '\\' && c1 == '\\')) {
            return false;
        }
    }

    for (const auto& part : path) {
        if (part == "..") {
            return false;
        }
        if (part.empty()) {
            return false;
        }
    }
    return true;
}

std::filesystem::path make_safe_output_path(const std::filesystem::path& output_root,
                                            const std::filesystem::path& archive_path) {
    if (!is_safe_relative_path(archive_path)) {
        throw InvalidArgument("unsafe archive path rejected during extraction");
    }
    return (output_root / archive_path).lexically_normal();
}

} // namespace bseal::archive
