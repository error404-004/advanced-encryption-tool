# src/encryption/utils.py

import ctypes
import logging

def secure_wipe(byte_array: bytearray):
    """
    Securely wipe the contents of a bytearray in memory.
    
    Args:
        byte_array (bytearray): The bytearray to be wiped.
    """
    length = len(byte_array)
    if length > 0:
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(byte_array)), 0, length)
        logging.debug(f"Securely wiped {length} bytes from memory.")

def bytes_to_hex(data: bytes) -> str:
    """
    Convert bytes to a hex string.

    Args:
        data (bytes): Input byte sequence.

    Returns:
        str: Hexadecimal representation.
    """
    return data.hex()

def hex_to_bytes(data_hex: str) -> bytes:
    """
    Convert a hex string to bytes.

    Args:
        data_hex (str): Hex string.

    Returns:
        bytes: Byte sequence.
    """
    return bytes.fromhex(data_hex)