# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)


def validate_hostname(hostname: str) -> bool:
    """
    Validate if the given string is a valid hostname.

    :param hostname: The hostname to validate.
    :return: True if valid, False otherwise.
    """

    if len(hostname) < 1 or len(hostname) > 63:
        return False

    if not hostname[0].isalpha():
        return False

    return hostname.replace('-', '').isalnum()


def validate_ipv4(ip: str) -> bool:
    """
    Validate if the given string is a valid IPv4 address.

    :param ip: The IP address to validate.
    :return: True if valid, False otherwise.
    """
    parts = ip.split('.')

    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit() or not (0 <= int(part) <= 255):
            return False

    return True


def validate_ipv6(ip: str) -> bool:
    """
    Validate if the given string is a valid IPv6 address.

    :param ip: The IP address to validate.
    :return: True if valid, False otherwise.
    """

    parts = ip.split(':')

    if len(parts) > 8:
        return False

    for part in parts:

        if len(part) == 0:
            continue

        try:
            value: int = int(part, 16)
        except ValueError:
            return False

        if value < 0 or value > 0xFFFF:
            return False

    return True
