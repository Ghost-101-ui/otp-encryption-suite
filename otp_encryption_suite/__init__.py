"""
OTP Encryption Suite

A secure One-Time Pad (OTP) encryption tool with hacker-style terminal interface.
"""

__version__ = "1.0.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from .core import (
    Colors,
    log,
    print_banner,
    print_status,
    print_section_header,
    print_progress_bar,
    loading_animation,
    next_index,
    build_name,
    sha256_hex,
    xor_bytes,
    generate_key_bytes,
    read_text_or_file,
    save_bytes,
    save_text,
    encrypt_flow,
    decrypt_flow,
    main
)

__all__ = [
    "Colors",
    "log",
    "print_banner",
    "print_status",
    "print_section_header",
    "print_progress_bar",
    "loading_animation",
    "next_index",
    "build_name",
    "sha256_hex",
    "xor_bytes",
    "generate_key_bytes",
    "read_text_or_file",
    "save_bytes",
    "save_text",
    "encrypt_flow",
    "decrypt_flow",
    "main"
]
