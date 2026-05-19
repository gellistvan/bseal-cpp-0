function(bseal_enable_sanitizers_if_requested target_name)
    if (NOT BSEAL_ENABLE_SANITIZERS)
        return()
    endif()

    if (MSVC)
        message(WARNING "BSEAL_ENABLE_SANITIZERS is not configured for MSVC in this skeleton.")
        return()
    endif()

    target_compile_options(${target_name} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${target_name} PRIVATE -fsanitize=address,undefined)
endfunction()
