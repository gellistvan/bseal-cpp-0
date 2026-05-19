#include "archive/PathSanitizer.hpp"

#include "common/Errors.hpp"

namespace bseal::archive {

bool is_safe_relative_path(const std::filesystem::path& path) {
    if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory()) {
        return false;
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
