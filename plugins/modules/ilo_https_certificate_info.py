#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_https_certificate_info
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Retrieves iLO HTTPS certificate information.
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
  type: raw
  returned: always
  description:
    - The configured HTTPS certificate information for the iLO device.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError

from typing import Optional

MODULE_INIT_ARGS: dict = dict(
    argument_spec=dict(),
    supports_check_mode=True
)

try:
    from redfish.rest.containers import RestResponse
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

        def get_https_certificate_info(self) -> dict:
            """
            Retrieve the HTTPS certificate information from the iLO device.

            Returns:
                dict: The HTTPS certificate information.
            """

            pass

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOHTTPSCertificateInfoModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO HTTPS certificate info modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

        def get_https_certificate_info(self) -> dict:
            """
            Retrieve the HTTPS certificate information from the iLO device.

            Returns:
                dict: The HTTPS certificate information.
            """

            https_certificate_uri: str = self.get_manager_security_https_cert_uri()

            try:
                response: RestResponse = self.client.get(https_certificate_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {https_certificate_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {https_certificate_uri}'))

            if 'X509CertificateInformation' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'X509CertificateInformation\' not found in {https_certificate_uri}'))

            return response.dict['X509CertificateInformation']


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
