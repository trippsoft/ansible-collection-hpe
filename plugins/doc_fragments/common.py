# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r"""
    options:
      base_url:
        type: str
        required: true
        description:
          - The IP address or hostname of the HPE iLO.
      username:
        type: str
        required: true
        description:
          - The username to authenticate with the HPE iLO.
      password:
        type: str
        required: true
        no_log: true
        description:
          - The password to authenticate with the HPE iLO.
      validate_certs:
        type: bool
        required: false
        default: true
        description:
          - Whether to validate SSL certificates.
    """
