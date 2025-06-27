#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_https_certificate
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures iLO HTTPS certificate
description:
  - >-
    This module configures the HTTPS certificate information for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  certificate:
    type: str
    required: true
    description:
      - The HTTPS certificate to be configured on the iLO device. This should be a PEM-encoded certificate.
  private_key:
    type: str
    required: false
    description:
      - The private key corresponding to the HTTPS certificate. This should be a PEM-encoded private key.
      - If not provided, the O(certificate) provided must be signed from the active certificate signing request (CSR).
  ca_bundle:
    type: str
    required: false
    description:
      - The CA bundle to be configured on the iLO device. This should be a PEM-encoded CA bundle.
"""

EXAMPLES = r"""
- name: Configure iLO HTTPS signed certificate
  trippsc2.hpe.ilo_https_certificate:
    base_uri: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    certificate: '{{ lookup("file", "path/to/certificate.pem") }}'
    ca_bundle: '{{ lookup("file", "path/to/ca_bundle.pem") }}'
  register: ilo_cert

- name: Configure iLO HTTPS self-signed certificate
  trippsc2.hpe.ilo_https_certificate:
    base_uri: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    certificate: '{{ lookup("file", "path/to/self_signed_certificate.pem") }}'
    private_key: '{{ lookup("file", "path/to/private_key.pem") }}'
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

import time
import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError

from typing import Optional

MODULE_INIT_ARGS: dict = dict(
    argument_spec=dict(
        certificate=dict(type='str', required=True),
        private_key=dict(type='str', required=False, no_log=True),
        ca_bundle=dict(type='str', required=False)
    ),
    supports_check_mode=True
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    # Stub class to allow ansible-test to run without Redfish
    class iLOHTTPSCertificateModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO HTTPS certificate modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

        def import_https_certificate(self, certificate: str, private_key: Optional[str], ca_bundle: Optional[str]) -> dict:
            """
            Imports the HTTPS certificate to the iLO device.

            Args:
                certificate (str): The PEM-encoded HTTPS certificate.
                private_key (Optional[str]): The PEM-encoded private key corresponding to the certificate.
                ca_bundle (Optional[str]): The PEM-encoded CA bundle.

            Returns:
                RestResponse: The response from the iLO device.
            """

            discard = certificate
            discard = private_key
            discard = ca_bundle

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        HAS_CRYPTOGRAPHY: bool = False
        CRYPTOGRAPHY_IMPORT_ERROR: Optional[str] = traceback.format_exc()

        # Stub class to allow ansible-test to run without Redfish
        class iLOHTTPSCertificateModule(iLOModule):
            """
            Extends iLOModule to simplify the creation of iLO HTTPS certificate modules.
            """

            def __init__(self, *args, **kwargs) -> None:
                super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

            def import_https_certificate(self, certificate: str, private_key: Optional[str], ca_bundle: Optional[str]) -> dict:
                """
                Imports the HTTPS certificate to the iLO device.

                Args:
                    certificate (str): The PEM-encoded HTTPS certificate.
                    private_key (Optional[str]): The PEM-encoded private key corresponding to the certificate.
                    ca_bundle (Optional[str]): The PEM-encoded CA bundle.

                Returns:
                    RestResponse: The response from the iLO device.
                """

                discard = certificate
                discard = private_key
                discard = ca_bundle

            def get_new_https_certificate_info(self) -> dict:
                """
                Gets the new HTTPS certificate information after import.

                Returns:
                    dict: The new HTTPS certificate information.
                """

                pass

    else:
        HAS_CRYPTOGRAPHY: bool = True
        CRYPTOGRAPHY_IMPORT_ERROR: Optional[str] = None

        class iLOHTTPSCertificateModule(iLOModule):
            """
            Extends iLOModule to simplify the creation of iLO HTTPS certificate modules.
            """

            def __init__(self, *args, **kwargs) -> None:
                super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

            def import_https_certificate(self, certificate: str, private_key: Optional[str], ca_bundle: Optional[str]) -> dict:
                """
                Imports the HTTPS certificate to the iLO device.

                Args:
                    certificate (str): The PEM-encoded HTTPS certificate.
                    private_key (Optional[str]): The PEM-encoded private key corresponding to the certificate.
                    ca_bundle (Optional[str]): The PEM-encoded CA bundle.

                Returns:
                    RestResponse: The response from the iLO device.
                """

                if not self.client:
                    self.fail_json(msg="Redfish client is not initialized")

                import_certificate_uri: str = self.get_https_cert_import_certificate_uri()

                certificate_data: str = ''

                if private_key is not None:
                    certificate_data += private_key + '\n'

                certificate_data += certificate + '\n'

                if ca_bundle is not None:
                    certificate_data += ca_bundle + '\n'

                payload: dict = {
                    'Certificate': certificate_data,
                }

                try:
                    response: RestResponse = self.client.post(import_certificate_uri, payload)
                except Exception as e:
                    self.handle_error(iLOModuleError('Error importing HTTPS certificate', exception=to_native(e)))

                if response.status != 200:
                    self.handle_error(iLOModuleError('Failed to import HTTPS certificate', response=response))

                return self.get_new_https_certificate_info()

            def get_new_https_certificate_info(self) -> dict:
                """
                Gets the new HTTPS certificate information after import.

                Returns:
                    dict: The new HTTPS certificate information.
                """

                time.sleep(30)

                for i in range(20):
                    time.sleep(i * 10)

                    try:
                        self.client.login()
                        break
                    except Exception as e:
                        # If login fails, it may indicate that the iLO is still resetting.
                        continue

                return self.get_https_certificate_info()


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOHTTPSCertificateModule = iLOHTTPSCertificateModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    if not HAS_CRYPTOGRAPHY:
        module.fail_json(
            msg=missing_required_lib('cryptography'),
            exception=CRYPTOGRAPHY_IMPORT_ERROR
        )

    certificate: str = module.params['certificate']
    certificate: str = certificate.strip(' \n\r\t')

    private_key: Optional[str] = module.params.get('private_key', None)

    if private_key is not None:
        private_key: str = private_key.strip(' \n\r\t')

    ca_bundle: Optional[str] = module.params.get('ca_bundle', None)

    if ca_bundle is not None:
        ca_bundle: str = ca_bundle.strip(' \n\r\t')

    try:
        certificate_data: x509.Certificate = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
    except ValueError as e:
        module.fail_json(
            msg="Invalid PEM-encoded certificate",
            exception=traceback.format_exc()
        )

    # TODO - Add validation for private key if provided

    serial_number: str = hex(certificate_data.serial_number)[2:].lower()
    serial_number: str = ':'.join(serial_number[i:i + 2] for i in range(0, len(serial_number), 2))

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    existing_certificate: dict = module.get_https_certificate_info()

    existing_serial_number: str = existing_certificate['serial_number'].lower()

    result['diff']['before']['certificate'] = existing_certificate

    if existing_serial_number == serial_number:
        result['diff']['after']['certificate'] = existing_certificate
        result['certificate_info'] = existing_certificate
    else:
        result['changed'] = True

        if module.check_mode:
            result['certificate_info'] = existing_certificate

            imported_certificate: dict = dict(
                serial_number=serial_number,
                issuer=certificate_data.issuer.rfc4514_string(),
                subject=certificate_data.subject.rfc4514_string(),
                valid_not_after=certificate_data.not_valid_after.isoformat(format='seconds'),
                valid_not_before=certificate_data.not_valid_before.isoformat(format='seconds')
            )
        else:
            imported_certificate: dict = module.import_https_certificate(certificate, private_key, ca_bundle)

            result['diff']['after']['certificate'] = imported_certificate
            result['certificate_info'] = imported_certificate

    module.logout()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
