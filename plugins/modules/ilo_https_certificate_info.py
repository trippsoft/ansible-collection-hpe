#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_https_certificate_info
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Retrieves iLO HTTPS certificate information
description:
  - >-
    This module retrieves the HTTPS certificate information for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
"""

EXAMPLES = r"""
- name: Get iLO HTTPS certificate info
  trippsc2.hpe.ilo_https_certificate_info:
    base_uri: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
  register: ilo_cert
"""

RETURN = r"""
certificate_info:
  type: dict
  returned: always
  description:
    - The configured HTTPS certificate information for the iLO device.
  contains:
    issuer:
      type: str
      description:
        - The issuer of the HTTPS certificate.
    subject:
      type: str
      description:
        - The subject of the HTTPS certificate.
    valid_not_after:
      type: str
      description:
        - The date and time after which the HTTPS certificate is no longer valid.
        - This is in ISO 8601 format.
    valid_not_before:
      type: str
      description:
        - The date and time before which the HTTPS certificate is not valid.
        - This is in ISO 8601 format.
"""

import traceback

from ..module_utils.ilo_module import iLOModule

from typing import Optional

MODULE_INIT_ARGS: dict = dict(
    argument_spec=dict(),
    supports_check_mode=True
)

try:
    import redfish
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    # Stub class to allow ansible-test to run without Redfish
    class iLOHTTPSCertificateInfoModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO HTTPS certificate info modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOHTTPSCertificateInfoModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO HTTPS certificate info modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)


def run_module() -> None:

    module: iLOHTTPSCertificateInfoModule = iLOHTTPSCertificateInfoModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg='Redfish client is not available',
            exception=REDFISH_IMPORT_ERROR
        )

    module.initialize_client()

    result: dict = dict(changed=False)

    result['certificate_info'] = module.get_https_certificate_info()

    module.logout()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
