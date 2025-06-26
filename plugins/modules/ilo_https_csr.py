#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_https_csr
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Generates an iLO HTTPS certificate signing request (CSR)
description:
  - >-
    This module generates an HTTPS certificate signing request (CSR) for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode_none
  - trippsc2.hpe.common
options:
  common_name:
    type: str
    required: true
    description:
      - The common name (CN) for the CSR, typically the fully qualified domain name (FQDN) of the iLO device.
      - This should be between 1 and 60 characters long.
  organization:
    type: str
    required: true
    description:
      - The organization name for the CSR.
      - This should be between 1 and 60 characters long.
  organizational_unit:
    type: str
    required: false
    description:
      - The organizational unit name for the CSR.
      - This should be between 1 and 60 characters long.
  city:
    type: str
    required: true
    description:
      - The city name for the CSR.
      - This should be between 1 and 50 characters long.
  state:
    type: str
    required: true
    description:
      - The state or province name for the CSR.
      - This should be between 1 and 30 characters long.
  country:
    type: str
    required: true
    description:
      - The two-letter country code for the CSR, following ISO 3166-1 alpha-2 format.
  include_ip_addresses:
    type: bool
    required: false
    default: false
    description:
      - Whether to include the iLO device's IP addresses in the CSR.
      - If V(true), the CSR will include the iLO device's IP addresses as subject alternative names (SANs).
      - If V(false), the CSR will not include IP addresses.
"""

EXAMPLES = r"""
- name: Generate iLO HTTPS CSR
  trippsc2.hpe.ilo_https_csr:
    base_uri: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    common_name: 'ilo.example.com'
    organization: 'Example Corp'
    organizational_unit: 'IT Department'
    city: 'City'
    state: 'State'
    country: 'US'
    include_ip_addresses: true
  register: ilo_csr
"""

RETURN = r"""
csr:
  type: str
  returned: always
  description:
    - The generated HTTPS certificate signing request (CSR) for the iLO device.
"""

import time
import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError

from typing import Optional

MODULE_INIT_ARGS: dict = dict(
    argument_spec=dict(
        common_name=dict(type='str', required=True),
        organization=dict(type='str', required=True),
        organizational_unit=dict(type='str', required=False),
        city=dict(type='str', required=True),
        state=dict(type='str', required=True),
        country=dict(type='str', required=True),
        include_ip_addresses=dict(type='bool', required=False, default=False)
    ),
    supports_check_mode=False
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    class iLOHTTPSCSRModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO HTTPS CSR modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

        def get_current_csr(self) -> Optional[str]:
            """
            Gets the current stored CSR from the iLO device.

            Returns:
                Optional[str]: The current stored CSR.
            """

            pass

        def generate_csr(self) -> None:
            """
            Generates a new HTTPS CSR for the iLO device.
            """

            pass

        def get_new_csr(self, old_csr: Optional[str]) -> str:
            """
            Gets the new CSR after generation.

            Args:
                old_csr (Optional[str]): The old CSR to compare against.

            Returns:
                str: The new CSR.
            """

            discard = old_csr

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOHTTPSCSRModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO HTTPS CSR modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

        def get_current_csr(self) -> Optional[str]:
            """
            Gets the current stored CSR from the iLO device.

            Returns:
                Optional[str]: The current stored CSR.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized.')

            https_certificate_uri: str = self.get_manager_security_https_cert_uri()

            try:
                response: RestResponse = self.client.get(https_certificate_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(f'Error retrieving current {https_certificate_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(f'Failed to retrieve {https_certificate_uri}'))

            if 'CertificateSigningRequest' in response.dict:
                return response.dict['CertificateSigningRequest']

            return None

        def generate_csr(self) -> None:
            """
            Generates a new HTTPS CSR for the iLO device.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized.')

            generate_csr_uri: str = self.get_https_cert_generate_csr_uri()

            payload: dict = dict(
                CommonName=self.params['common_name'],
                OrgName=self.params['organization'],
                City=self.params['city'],
                State=self.params['state'],
                Country=self.params['country'],
                IncludeIP=self.params['include_ip_addresses']
            )

            if self.params.get('organizational_unit', None) is not None:
                payload['OrgUnit'] = self.params['organizational_unit']

            try:
                response: RestResponse = self.client.post(generate_csr_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError('Error generating CSR', exception=to_native(e)))

            if response.status not in [200, 201, 204]:
                self.handle_error(iLOModuleError('Failed to generate CSR'))

        def get_new_csr(self, old_csr: Optional[str]) -> str:
            """
            Gets the new CSR after generation.

            Args:
                old_csr (Optional[str]): The old CSR to compare against.

            Returns:
                str: The new CSR.
            """

            for i in range(30):
                time.sleep(i * 10)

                new_csr: Optional[str] = self.get_current_csr()

                if new_csr is not None and new_csr != old_csr:
                    return new_csr

            self.handle_error(iLOModuleError('Failed to retrieve new CSR after generation'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOHTTPSCSRModule = iLOHTTPSCSRModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    module.initialize_client()

    result: dict = dict(changed=True)

    old_csr: Optional[str] = module.get_current_csr()

    module.generate_csr()
    result['csr'] = module.get_new_csr(old_csr)

    module.logout()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
