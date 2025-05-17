# src/encryption/fips_validator.py

import subprocess
import logging
import platform

def is_fips_mode_enabled() -> bool:
    """
    Check if the system is running in FIPS mode (Linux only).

    Returns:
        bool: True if FIPS mode is enabled, False otherwise.
    """
    try:
        with open("/proc/sys/crypto/fips_enabled", "r") as f:
            status = f.read().strip()
            return status == "1"
    except FileNotFoundError:
        logging.warning("FIPS check not available on this OS.")
        return False

def validate_library_fips_support(lib_name: str) -> bool:
    """
    Simulate FIPS validation for a given cryptographic library.

    Args:
        lib_name (str): Name of the library (e.g., 'cryptography', 'PyKCS11').

    Returns:
        bool: True if library is known to support FIPS mode, False otherwise.
    """
    supported_libs = ["cryptography", "PyKCS11"]
    if lib_name in supported_libs:
        logging.info(f"{lib_name} is known to support FIPS-compliant backends.")
        return True
    else:
        logging.warning(f"{lib_name} is not confirmed FIPS compliant.")
        return False

def get_platform_fips_info() -> str:
    """
    Return basic platform and FIPS status information.

    Returns:
        str: Platform and FIPS info.
    """
    os_info = f"OS: {platform.system()} {platform.release()}"
    fips_status = "ENABLED" if is_fips_mode_enabled() else "DISABLED"
    return f"{os_info} | FIPS Mode: {fips_status}"