#include "app/BsealApp.hpp"

#include "archive/ArchiveReader.hpp"
#include "archive/ArchiveWriter.hpp"
#include "archive/RecordFormat.hpp"
#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "crypto/AesGcmBackend.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
#include "crypto/KeySchedule.hpp"
#include "crypto/SecureBuffer.hpp"
#include "crypto/XChaCha20Poly1305Backend.hpp"
#include "io/ShardReader.hpp"
#include "io/ShardWriter.hpp"
#include "pipeline/DecryptPipeline.hpp"
#include "pipeline/EncryptPipeline.hpp"
#include "platform/Random.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace bseal::app {
    namespace {

        using bseal::Byte;
        using bseal::Bytes;
        using bseal::ConstByteSpan;

        struct ArchiveOpenContext {
            bseal::crypto::CipherSuite suite{bseal::crypto::CipherSuite::XChaCha20Poly1305};
            bseal::crypto::KdfParams kdf_params{};
            bseal::archive::PublicHeaderV1 public_header{};
            std::array<Byte, 32> kdf_salt{};
            std::array<Byte, 16> archive_id{};
            std::array<Byte, 32> public_header_hash{};
            std::uint64_t chunk_plain_size{16ull * 1024ull * 1024ull};
        };

        std::string read_line_from_stdin(std::string_view prompt) {
            std::cerr << prompt;
            std::string line;
            std::getline(std::cin, line);
            if (!std::cin) {
                throw bseal::InvalidArgument("failed to read passphrase from stdin");
            }
            return line;
        }

#if defined(_WIN32)
        std::string prompt_hidden(std::string_view prompt) {
            std::cerr << prompt;

            HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
            if (input == INVALID_HANDLE_VALUE) {
                throw bseal::InvalidArgument("failed to access console input");
            }

            DWORD old_mode = 0;
            if (!GetConsoleMode(input, &old_mode)) {
                return read_line_from_stdin(prompt);
            }

            DWORD new_mode = old_mode;
            new_mode &= ~ENABLE_ECHO_INPUT;
            if (!SetConsoleMode(input, new_mode)) {
                throw bseal::InvalidArgument("failed to disable console echo");
            }

            std::string line;
            std::getline(std::cin, line);
            SetConsoleMode(input, old_mode);
            std::cerr << '\n';

            if (!std::cin) {
                throw bseal::InvalidArgument("failed to read passphrase from stdin");
            }
            return line;
        }
#else
        std::string prompt_hidden(std::string_view prompt) {
            std::cerr << prompt;

            termios old_termios{};
            if (tcgetattr(STDIN_FILENO, &old_termios) != 0) {
                return read_line_from_stdin(prompt);
            }

            termios new_termios = old_termios;
            new_termios.c_lflag &= static_cast<unsigned int>(~ECHO);
            if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_termios) != 0) {
                throw bseal::InvalidArgument("failed to disable terminal echo");
            }

            std::string line;
            std::getline(std::cin, line);
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
            std::cerr << '\n';

            if (!std::cin) {
                throw bseal::InvalidArgument("failed to read passphrase from stdin");
            }
            return line;
        }
#endif

        std::string obtain_passphrase(bool passphrase_prompt) {
            if (passphrase_prompt) {
                auto first = prompt_hidden("Passphrase: ");
                auto second = prompt_hidden("Confirm passphrase: ");
                if (first != second) {
                    throw bseal::InvalidArgument("passphrases do not match");
                }
                if (first.empty()) {
                    throw bseal::InvalidArgument("passphrase must not be empty");
                }
                return first;
            }

            auto passphrase = read_line_from_stdin("Passphrase: ");
            if (passphrase.empty()) {
                throw bseal::InvalidArgument("passphrase must not be empty");
            }
            return passphrase;
        }

        std::unique_ptr<bseal::crypto::CryptoBackend>
        make_backend(bseal::crypto::CipherSuite suite) {
            switch (suite) {
            case bseal::crypto::CipherSuite::XChaCha20Poly1305:
                return std::make_unique<bseal::crypto::XChaCha20Poly1305Backend>();
            case bseal::crypto::CipherSuite::Aes256Gcm:
                return std::make_unique<bseal::crypto::AesGcmBackend>();
            }
            throw bseal::InvalidArgument("unsupported cipher suite");
        }

        std::uint16_t suite_to_header_id(bseal::crypto::CipherSuite suite) {
            return static_cast<std::uint16_t>(suite);
        }

        bseal::crypto::CipherSuite suite_from_header_id(std::uint16_t suite_id) {
            switch (static_cast<bseal::crypto::CipherSuite>(suite_id)) {
            case bseal::crypto::CipherSuite::XChaCha20Poly1305:
                return bseal::crypto::CipherSuite::XChaCha20Poly1305;
            case bseal::crypto::CipherSuite::Aes256Gcm:
                return bseal::crypto::CipherSuite::Aes256Gcm;
            }
            throw bseal::InvalidArgument("archive uses an unsupported cipher suite");
        }

        void require_path_exists(const std::filesystem::path &path, std::string_view description) {
            if (!std::filesystem::exists(path)) {
                throw bseal::InvalidArgument(std::string(description) +
                                             " does not exist: " + path.string());
            }
        }

        void require_directory(const std::filesystem::path &path, std::string_view description) {
            require_path_exists(path, description);
            if (!std::filesystem::is_directory(path)) {
                throw bseal::InvalidArgument(std::string(description) +
                                             " is not a directory: " + path.string());
            }
        }

        void require_keyfiles_exist(const std::vector<std::filesystem::path> &keyfiles) {
            if (keyfiles.empty()) {
                throw bseal::InvalidArgument("at least one --keyfile is required");
            }

            for (const auto &keyfile : keyfiles) {
                require_path_exists(keyfile, "keyfile");
                if (!std::filesystem::is_regular_file(keyfile)) {
                    throw bseal::InvalidArgument("keyfile is not a regular file: " +
                                                 keyfile.string());
                }
            }
        }

        template <std::size_t N> std::array<Byte, N> random_array() {
            std::array<Byte, N> out{};
            bseal::platform::fill_secure_random(std::span<Byte>{out.data(), out.size()});
            return out;
        }

        bseal::archive::PublicHeaderV1 make_encrypt_public_header(
            const bseal::cli::EncryptOptions &options, const std::array<Byte, 16> &archive_id,
            const std::array<Byte, 32> &kdf_salt, const bseal::crypto::KdfParams &kdf_params) {
            bseal::archive::PublicHeaderV1 header{};
            header.version = 1;
            header.suite_id = suite_to_header_id(options.suite);
            header.archive_id = archive_id;
            header.shard_index = 0;
            header.kdf_salt = kdf_salt;
            header.argon2_memory_kib = kdf_params.memory_kib;
            header.argon2_iterations = kdf_params.iterations;
            header.argon2_parallelism = kdf_params.parallelism;
            header.chunk_plain_size = static_cast<std::uint32_t>(options.chunk_size);
            header.shard_payload_size = options.shard_size;

            // header_mac is a keyed MAC and is intentionally not computed here.
            // It must never be used as public_header_hash.
            //
            // public_header_hash is computed separately with
            // archive::compute_public_header_hash(header), which canonicalizes the public
            // header and zeroes header_mac before hashing.
            //
            // Real header_mac generation/verification is a later task.
            return header;
        }

        ArchiveOpenContext make_encrypt_context(const bseal::cli::EncryptOptions &options) {
            ArchiveOpenContext context{};
            context.suite = options.suite;
            context.kdf_params = bseal::crypto::preset_params(options.kdf_preset);
            bseal::crypto::validate_kdf_params(context.kdf_params);
            context.kdf_salt = random_array<32>();
            context.archive_id = random_array<16>();
            context.chunk_plain_size = options.chunk_size;

            auto header = make_encrypt_public_header(options, context.archive_id, context.kdf_salt,
                                                     context.kdf_params);
            context.public_header_hash = bseal::archive::compute_public_header_hash(header);
            context.public_header = header;
            return context;
        }

        std::vector<std::filesystem::path> find_bin_files(const std::filesystem::path &input_dir) {
            std::vector<std::filesystem::path> result;
            for (const auto &entry : std::filesystem::directory_iterator(input_dir)) {
                if (entry.is_regular_file() && entry.path().extension() == ".bin") {
                    result.push_back(entry.path());
                }
            }

            std::sort(result.begin(), result.end());
            if (result.empty()) {
                throw bseal::InvalidArgument(
                    "input directory does not contain any .bin shard files");
            }
            return result;
        }

        Bytes read_prefix(const std::filesystem::path &path, std::size_t max_bytes) {
            std::ifstream in(path, std::ios::binary);
            if (!in) {
                throw bseal::InvalidArgument("failed to open shard file: " + path.string());
            }

            Bytes bytes(max_bytes);
            in.read(reinterpret_cast<char *>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()));
            bytes.resize(static_cast<std::size_t>(in.gcount()));
            if (bytes.empty()) {
                throw bseal::InvalidArgument("shard file is empty: " + path.string());
            }
            return bytes;
        }

        bseal::archive::PublicHeaderV1
        read_first_public_header(const std::filesystem::path &input_dir) {
            /*
            Expected production behavior:
            - ShardReader::discover() or an archive opener should parse all public headers;
            - verify archive_id consistency;
            - verify shard indices and shard counts;
            - expose the canonical public header/context to main.

            This fallback reads a generous prefix from the first .bin and passes it to
            parse_public_header(). If your implemented ShardReader exposes a stronger API, prefer
            that instead.
            */
            const auto bin_files = find_bin_files(input_dir);
            constexpr std::size_t kMaxPublicHeaderProbeBytes = 4096;
            auto prefix = read_prefix(bin_files.front(), kMaxPublicHeaderProbeBytes);
            return bseal::archive::parse_public_header(ConstByteSpan{prefix.data(), prefix.size()});
        }

        ArchiveOpenContext make_decrypt_context_from_shards(
            const std::vector<bseal::io::ShardInfo>& shards) {
            auto first = std::find_if(
                shards.begin(),
                shards.end(),
                [](const bseal::io::ShardInfo& shard) {
                    return shard.shard_index == 0;
                });

            if (first == shards.end()) {
                throw bseal::InvalidArgument(
                    "missing shard_index 0; cannot open archive public header");
            }

            const auto& header = first->public_header;

            ArchiveOpenContext context{};
            context.public_header = header;
            context.suite = suite_from_header_id(header.suite_id);

            context.kdf_params.preset = bseal::crypto::KdfPreset::Custom;
            context.kdf_params.memory_kib = header.argon2_memory_kib;
            context.kdf_params.iterations = header.argon2_iterations;
            context.kdf_params.parallelism = header.argon2_parallelism;
            context.kdf_params.output_bytes = bseal::crypto::kArgon2OutputBytesDefault;
            bseal::crypto::validate_kdf_params(context.kdf_params);

            context.kdf_salt = header.kdf_salt;
            context.archive_id = header.archive_id;
            context.chunk_plain_size = header.chunk_plain_size;
            context.public_header_hash = bseal::archive::compute_public_header_hash(header);

            if (first->public_header_hash != context.public_header_hash) {
                throw bseal::InvalidArgument("public_header_hash mismatch in shard_index 0");
            }

            return context;
        }

        bseal::crypto::ExpandedKeys
        derive_expanded_keys(const ArchiveOpenContext &context, std::string passphrase,
                             const std::vector<std::filesystem::path> &keyfiles) {
            bseal::crypto::KdfInput input;
            input.passphrase_utf8 = std::move(passphrase);
            input.keyfiles = keyfiles;
            input.salt = context.kdf_salt;
            input.archive_id = context.archive_id;
            input.params = context.kdf_params;

            auto master_seed = bseal::crypto::derive_master_seed(input);
            return bseal::crypto::expand_keys(master_seed.as_span(), context.suite);
        }

    } // namespace

    int encrypt(const bseal::cli::EncryptOptions &options) {
        require_directory(options.input, "input path");
        require_keyfiles_exist(options.keyfiles);
        std::filesystem::create_directories(options.output);

        auto context = make_encrypt_context(options);
        auto passphrase = obtain_passphrase(options.passphrase_prompt);
        auto keys = derive_expanded_keys(context, std::move(passphrase), options.keyfiles);

        bseal::archive::ArchiveWriter archive_writer(bseal::archive::ArchiveWriterOptions{
            options.input,
            options.chunk_size,
            true,
            true,
            false,
        });

        bseal::io::ShardWriterOptions shard_options{};
        shard_options.output_dir = options.output;
        shard_options.max_shard_payload_size = options.shard_size;
        shard_options.filename_extension = ".bin";

        shard_options.suite_id = suite_to_header_id(context.suite);
        shard_options.archive_id = context.archive_id;
        shard_options.chunk_plain_size = context.chunk_plain_size;
        shard_options.public_header_hash = context.public_header_hash;
        shard_options.public_header = context.public_header;

        bseal::io::ShardWriter shard_writer(std::move(shard_options));

        bseal::pipeline::EncryptPipelineOptions pipeline_options;
        pipeline_options.chunk_plain_size = options.chunk_size;
        pipeline_options.worker_count = 0;
        pipeline_options.queue_depth = 0;
        pipeline_options.archive_id = context.archive_id;
        pipeline_options.public_header_hash = context.public_header_hash;
        pipeline_options.aad_shard_index = 0;
        pipeline_options.emit_final_chunk_when_empty = true;

        bseal::pipeline::EncryptPipeline pipeline(pipeline_options, make_backend(context.suite),
                                                  std::move(keys), std::move(archive_writer),
                                                  std::move(shard_writer));

        pipeline.run();
        return 0;
    }

    int decrypt(const bseal::cli::DecryptOptions &options) {
        require_directory(options.input, "input path");
        require_keyfiles_exist(options.keyfiles);

        if (std::filesystem::exists(options.output) && !options.overwrite) {
            if (!std::filesystem::is_empty(options.output)) {
                throw bseal::InvalidArgument(
                    "output directory already exists and is not empty; use --overwrite");
            }
        }

        std::filesystem::create_directories(options.output);

        auto shards = bseal::io::ShardReader::discover(options.input);
        auto context = make_decrypt_context_from_shards(shards);

        auto passphrase = obtain_passphrase(options.passphrase_prompt);
        auto keys = derive_expanded_keys(context, std::move(passphrase), options.keyfiles);

        bseal::io::ShardReaderValidation validation{};
        validation.suite_id = suite_to_header_id(context.suite);
        validation.archive_id = context.archive_id;
        validation.chunk_plain_size = context.chunk_plain_size;
        validation.public_header_hash = context.public_header_hash;

        bseal::io::ShardReader shard_reader(std::move(shards), validation);
        bseal::archive::ArchiveReader archive_reader(bseal::archive::ArchiveReaderOptions{
            options.output,
            options.overwrite,
            true,
            true,
            false,
        });

        bseal::pipeline::DecryptPipelineOptions pipeline_options;
        pipeline_options.chunk_plain_size = context.chunk_plain_size;
        pipeline_options.worker_count = 0;
        pipeline_options.queue_depth = 0;
        pipeline_options.archive_id = context.archive_id;
        pipeline_options.public_header_hash = context.public_header_hash;
        pipeline_options.aad_shard_index = 0;

        bseal::pipeline::DecryptPipeline pipeline(pipeline_options, make_backend(context.suite),
                                                  std::move(keys), std::move(shard_reader),
                                                  std::move(archive_reader));

        pipeline.run();
        return 0;
    }

} // namespace bseal::app
