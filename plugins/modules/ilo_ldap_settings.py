#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_ldap_settings
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configure iLO LDAP settings
description:
  - >-
    This module configures the LDAP settings for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  local_account_auth_enabled:
    type: bool
    required: false
    description:
      - Whether to enable local account authentication on the iLO device.
      - If O(state=disabled), this option must be set to V(true).
      - If O(state=disabled) and this option is not provided, it defaults to V(true).
  ldap_ca_certificate:
    type: str
    required: false
    description:
      - The CA certificate for the LDAP server.
      - If O(state=active_directory) or O(state=generic_ldap), this option is required.
      - If O(state=disabled), this option should not be provided.
  ldap_servers:
    type: list
    required: false
    elements: dict
    description:
      - A list of LDAP server configurations.
      - If O(state=active_directory) or O(state=generic_ldap), this option is required.
      - If O(state=disabled), this option should not be provided.
    suboptions:
      address:
        type: str
        required: true
        description:
          - The address of the LDAP server.
          - This can be an IP address or an FQDN.
      port:
        type: int
        required: false
        default: 636
        description:
          - The port number for the LDAP server.
  ldap_username:
    type: str
    required: false
    description:
      - The username for the LDAP server.
      - If O(state=active_directory) or O(state=generic_ldap), this option is required.
      - If O(state=disabled), this option should not be provided.
  ldap_password:
    type: str
    required: false
    description:
      - The password for the LDAP server.
      - If O(state=active_directory) or O(state=generic_ldap), this option is required.
      - If O(state=disabled), this option should not be provided.
  ldap_search_bases:
    type: list
    required: false
    elements: str
    description:
      - A list of LDAP search bases.
      - If O(state=active_directory) or O(state=generic_ldap), this option is required.
      - If O(state=disabled), this option should not be provided.
  use_extended_schema:
    type: bool
    required: false
    default: false
    description:
      - Whether to use the extended schema for LDAP.
      - If O(state=generic_ldap) or O(state=disabled), this option is ignored.
  update_password:
    type: str
    required: false
    default: when_changed
    choices:
      - when_changed
      - always
    description:
      - Determines when the LDAP password should be updated.
      - If set to V(when_changed), the password will only be updated if other LDAP settings change.
      - If set to V(always), the password will be updated every time the module is run.  This makes the module not idempotent.
      - This option is only applicable when O(state=active_directory) or O(state=generic_ldap).
      - If O(state=disabled), this option is ignored.
  state:
    type: str
    required: true
    choices:
      - active_directory
      - generic_ldap
      - disabled
    description:
      - The state of the LDAP configuration on the iLO device.
      - If set to V(active_directory), the iLO device will be configured to use Active Directory for authentication.
      - If set to V(generic_ldap), the iLO device will be configured to use a generic LDAP server for authentication.
      - If set to V(disabled), the LDAP configuration will be disabled.
"""

EXAMPLES = r"""
- name: Configure iLO LDAP settings
  trippsc2.hpe.ilo_ldap_settings:
    base_url: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    local_account_auth_enabled: true
    ldap_ca_certificate: '{{ lookup("file", "path/to/ca_certificate.pem") }}'
    ldap_servers:
      - address: 'ldap.example.com'
        port: 636
    ldap_username: 'cn=admin,dc=example,dc=com'
    ldap_password: 'admin_password'
    ldap_search_bases:
      - 'dc=example,dc=com'
    use_extended_schema: true
    state: active_directory

- name: Disable iLO LDAP settings
  trippsc2.hpe.ilo_ldap_settings:
    base_url: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    state: disabled
"""

RETURN = r"""
local_account_auth_enabled:
  type: bool
  returned: always
  description:
    - Indicates whether local account authentication is enabled on the iLO device.
ldap_ca_certificate_serial_number:
  type: str
  returned: O(state=active_directory) or O(state=generic_ldap)
  description:
    - The serial number of the CA certificate used for LDAP authentication.
ldap_servers:
  type: list
  returned: O(state=active_directory) or O(state=generic_ldap)
  elements: dict
  description:
    - A list of LDAP server configurations.
  contains:
    address:
      type: str
      description:
        - The address of the LDAP server.
    port:
      type: int
      description:
        - The port number for the LDAP server.
ldap_username:
  type: str
  returned: O(state=active_directory) or O(state=generic_ldap)
  description:
    - The username used for LDAP authentication.
ldap_search_bases:
  type: list
  returned: O(state=active_directory) or O(state=generic_ldap)
  elements: str
  description:
    - A list of LDAP search bases used for user lookups.
use_extended_schema:
  type: bool
  returned: O(state=active_directory)
  description:
    - Indicates whether the extended schema is used for LDAP.
state:
  type: str
  returned: always
  description:
    - The state of the LDAP configuration on the iLO device.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError

from typing import List, Optional

MODULE_INIT_ARGS: dict = dict(
    argument_spec=dict(
        local_account_auth_enabled=dict(type='bool', required=False),
        ldap_ca_certificate=dict(type='str', required=False),
        ldap_servers=dict(
            type='list',
            required=False,
            elements='dict',
            options=dict(
                address=dict(type='str', required=True),
                port=dict(type='int', required=False, default=636)
            )
        ),
        ldap_username=dict(type='str', required=False),
        ldap_password=dict(type='str', required=False, no_log=True),
        ldap_search_bases=dict(type='list', required=False, elements='str'),
        use_extended_schema=dict(type='bool', required=False, default=False),
        update_password=dict(type='str', required=False, default='when_changed', choices=['when_changed', 'always'], no_log=False),
        state=dict(type='str', required=True, choices=['active_directory', 'generic_ldap', 'disabled'])
    ),
    required_if=[
        ('state', 'active_directory', ['ldap_ca_certificate', 'ldap_servers', 'ldap_username', 'ldap_password', 'ldap_search_bases']),
        ('state', 'generic_ldap', ['ldap_ca_certificate', 'ldap_servers', 'ldap_username', 'ldap_password', 'ldap_search_bases'])
    ],
    supports_check_mode=True
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    class iLOAccountSettingsModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO security settings modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

        def get_desired_settings(self) -> dict:
            """
            Get the desired security settings from the module parameters.

            Returns:
                dict: The desired security settings.
            """

            pass

        def get_current_settings(self) -> dict:
            """
            Get the current security settings from the iLO device.

            Returns:
                dict: The current security settings.
            """

            pass

        def get_changes_needed(self, current_settings: dict, desired_settings: dict) -> dict:
            """
            Determine the changes needed to apply the desired security settings.

            Args:
                current_settings (dict): The current security settings.
                desired_settings (dict): The desired security settings.

            Returns:
                dict: The changes needed to apply the desired settings.
            """

            discard = current_settings
            discard = desired_settings

        def apply_settings(self, changes_needed: dict, has_existing_cert: bool) -> None:
            """
            Apply the changes needed to the iLO device.

            Args:
                changes_needed (dict): The changes needed to apply the desired settings.
            """

            discard = changes_needed
            discard = has_existing_cert

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        HAS_CRYPTOGRAPHY: bool = False
        CRYPTOGRAPHY_IMPORT_ERROR: Optional[str] = traceback.format_exc()

        class iLOAccountSettingsModule(iLOModule):
            """
            Extends iLOModule to simplify the creation of iLO security settings modules.
            """

            def __init__(self, *args, **kwargs) -> None:
                super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

            def get_desired_settings(self) -> dict:
                """
                Get the desired security settings from the module parameters.

                Returns:
                    dict: The desired security settings.
                """

                pass

            def get_current_settings(self) -> dict:
                """
                Get the current security settings from the iLO device.

                Returns:
                    dict: The current security settings.
                """

                pass

            def get_changes_needed(self, current_settings: dict, desired_settings: dict) -> dict:
                """
                Determine the changes needed to apply the desired security settings.

                Args:
                    current_settings (dict): The current security settings.
                    desired_settings (dict): The desired security settings.

                Returns:
                    dict: The changes needed to apply the desired settings.
                """

                discard = current_settings
                discard = desired_settings

            def apply_settings(self, changes_needed: dict, has_existing_cert: bool) -> None:
                """
                Apply the changes needed to the iLO device.

                Args:
                    changes_needed (dict): The changes needed to apply the desired settings.
                """

                discard = changes_needed
                discard = has_existing_cert

    else:
        HAS_CRYPTOGRAPHY: bool = True
        CRYPTOGRAPHY_IMPORT_ERROR: Optional[str] = None

        class iLOAccountSettingsModule(iLOModule):
            """
            Extends iLOModule to simplify the creation of iLO security settings modules.
            """

            def __init__(self, *args, **kwargs) -> None:
                super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

            def get_desired_settings(self) -> dict:
                """
                Get the desired security settings from the module parameters.

                Returns:
                    dict: The desired security settings.
                """

                desired_settings: dict = dict()

                state: str = self.params['state']

                desired_settings['state'] = state

                if self.params.get('local_account_auth_enabled', None) is not None:
                    desired_settings['local_account_auth_enabled'] = self.params['local_account_auth_enabled']

                if state == 'disabled':
                    return desired_settings

                if self.params.get('ldap_servers', None) is not None:
                    desired_settings['ldap_servers'] = self.params['ldap_servers']

                if self.params.get('ldap_username', None) is not None:
                    desired_settings['ldap_username'] = self.params['ldap_username']

                if self.params.get('ldap_password', None) is not None:
                    desired_settings['ldap_password'] = self.params['ldap_password']

                if self.params.get('ldap_search_bases', None) is not None:
                    desired_settings['ldap_search_bases'] = self.params['ldap_search_bases']

                if state == 'generic_ldap':
                    return desired_settings

                if self.params.get('use_extended_schema', None) is not None:
                    desired_settings['use_extended_schema'] = self.params['use_extended_schema']

                return desired_settings

            def get_current_settings(self) -> dict:
                """
                Get the current security settings from the iLO device.

                Returns:
                    dict: The current security settings.
                """

                if not self.client:
                    self.fail_json(msg='Redfish client is not initialized.')

                account_service_uri: str = self.get_account_service_uri()

                try:
                    response: RestResponse = self.client.get(account_service_uri)
                except Exception as e:
                    self.handle_error(iLOModuleError(f'Error retrieving {account_service_uri}', exception=to_native(e)))

                if response.status != 200:
                    self.handle_error(iLOModuleError(f'Failed to retrieve {account_service_uri}'))

                if 'LocalAccountAuth' not in response.dict:
                    self.handle_error(iLOModuleError(f'\'LocalAccountAuth\' not found in {account_service_uri}'))

                local_account_auth_enabled: bool = response.dict['LocalAccountAuth'] == 'Enabled'

                if 'LDAP' not in response.dict:
                    self.handle_error(iLOModuleError(f'\'LDAP\' not found in {account_service_uri}'))

                ldap: dict = response.dict['LDAP']

                if 'ServiceEnabled' not in ldap:
                    self.handle_error(iLOModuleError(f'\'LDAP.ServiceEnabled\' not found in {account_service_uri}'))

                if not ldap['ServiceEnabled']:
                    return dict(state='disabled', local_account_auth_enabled=local_account_auth_enabled)

                if 'AccountProviderType' not in ldap:
                    self.handle_error(iLOModuleError(f'\'LDAP.AccountProviderType\' not found in {account_service_uri}'))

                if ldap['AccountProviderType'] == 'ActiveDirectoryService':
                    state: str = 'active_directory'
                elif ldap['AccountProviderType'] == 'LDAPService':
                    state: str = 'generic_ldap'
                else:
                    self.handle_error(iLOModuleError(f'Unknown LDAP account provider type: {ldap["AccountProviderType"]}'))

                if 'ServiceAddresses' not in ldap:
                    self.handle_error(iLOModuleError(f'\'LDAP.ServiceAddresses\' not found in {account_service_uri}'))

                service_addresses: List[str] = ldap['ServiceAddresses']

                ldap_servers: List[dict] = []

                for address in service_addresses:

                    split_address: List[str] = address.split(':')

                    if len(split_address) > 2:
                        self.handle_error(iLOModuleError(f'Invalid LDAP server address format: {address}'))
                    elif len(split_address) == 1:
                        ldap_servers.append(dict(address=split_address[0], port=636))
                    else:
                        ldap_servers.append(dict(address=split_address[0], port=int(split_address[1])))

                if 'Authentication' not in ldap:
                    self.handle_error(iLOModuleError(f'\'LDAP.Authentication\' not found in {account_service_uri}'))

                authentication: dict = ldap['Authentication']

                if 'Username' not in authentication:
                    self.handle_error(iLOModuleError(f'\'LDAP.Authentication.Username\' not found in {account_service_uri}'))

                ldap_username: str = authentication['Username']

                if 'LDAPService' not in ldap:
                    self.handle_error(iLOModuleError(f'\'LDAP.LDAPService\' not found in {account_service_uri}'))

                ldap_service: dict = ldap['LDAPService']

                if 'SearchSettings' not in ldap_service:
                    self.handle_error(iLOModuleError(f'\'LDAP.LDAPService.SearchSettings\' not found in {account_service_uri}'))

                search_settings: dict = ldap_service['SearchSettings']

                if 'BaseDistinguishedNames' not in search_settings:
                    self.handle_error(iLOModuleError(f'\'LDAP.LDAPService.SearchSettings.BaseDistinguishedNames\' not found in {account_service_uri}'))

                ldap_search_bases: List[str] = search_settings['BaseDistinguishedNames']

                if 'Certificates' not in ldap:
                    self.handle_error(iLOModuleError(f'\'LDAP.Certificates\' not found in {account_service_uri}'))

                certificates: dict = ldap['Certificates']

                if '@odata.id' not in certificates:
                    self.handle_error(iLOModuleError(f'\'LDAP.Certificates.@odata.id\' not found in {account_service_uri}'))

                certificates_uri: str = certificates['@odata.id']

                try:
                    response: RestResponse = self.client.get(certificates_uri)
                except Exception as e:
                    self.handle_error(iLOModuleError(f'Error retrieving {certificates_uri}', exception=to_native(e)))

                if response.status != 200:
                    self.handle_error(iLOModuleError(f'Failed to retrieve {certificates_uri}'))

                if 'Members' not in response.dict:
                    self.handle_error(iLOModuleError(f'\'Members\' not found in {certificates_uri}'))

                members: List[dict] = response.dict['Members']

                ldap_ca_certificate_serial_number: Optional[str] = None

                if len(members) > 0:
                    if '@odata.id' not in members[0]:
                        self.handle_error(iLOModuleError(f'\'Members[0].@odata.id\' not found in {certificates_uri}'))

                    certificate_uri: str = members[0]['@odata.id']

                    try:
                        response: RestResponse = self.client.get(certificate_uri)
                    except Exception as e:
                        self.handle_error(iLOModuleError(f'Error retrieving {certificate_uri}', exception=to_native(e)))

                    if response.status != 200:
                        self.handle_error(iLOModuleError(f'Failed to retrieve {certificate_uri}'))

                    if 'SerialNumber' not in response.dict:
                        self.handle_error(iLOModuleError(f'\'SerialNumber\' not found in {certificate_uri}'))

                    ldap_ca_certificate_serial_number: Optional[str] = response.dict['SerialNumber']

                if state == 'generic_ldap':
                    return dict(
                        local_account_auth_enabled=local_account_auth_enabled,
                        ldap_ca_certificate_serial_number=ldap_ca_certificate_serial_number,
                        ldap_servers=ldap_servers,
                        ldap_username=ldap_username,
                        ldap_search_bases=ldap_search_bases,
                        state=state
                    )

                if 'Oem' not in response.dict:
                    self.handle_error(iLOModuleError(f'\'Oem\' not found in {account_service_uri}'))

                oem: dict = response.dict['Oem']

                if 'Hpe' not in oem:
                    self.handle_error(iLOModuleError(f'\'Oem.Hpe\' not found in {account_service_uri}'))

                hpe: dict = oem['Hpe']

                if 'DirectorySettings' not in hpe:
                    self.handle_error(iLOModuleError(f'\'Oem.Hpe.DirectorySettings\' not found in {account_service_uri}'))

                directory_settings: dict = hpe['DirectorySettings']

                if 'LdapAuthenticationMode' not in directory_settings:
                    self.handle_error(iLOModuleError(f'\'Oem.Hpe.DirectorySettings.LdapAuthenticationMode\' not found in {account_service_uri}'))

                use_extended_schema: bool = directory_settings['LdapAuthenticationMode'] == 'ExtendedSchema'

                return dict(
                    local_account_auth_enabled=local_account_auth_enabled,
                    ldap_ca_certificate_serial_number=ldap_ca_certificate_serial_number,
                    ldap_servers=ldap_servers,
                    ldap_username=ldap_username,
                    ldap_search_bases=ldap_search_bases,
                    use_extended_schema=use_extended_schema,
                    state=state
                )

            def get_changes_needed(self, current_settings: dict, desired_settings: dict) -> dict:
                """
                Determine the changes needed to apply the desired security settings.

                Args:
                    current_settings (dict): The current security settings.
                    desired_settings (dict): The desired security settings.

                Returns:
                    dict: The changes needed to apply the desired settings.
                """

                changes_needed: dict = dict()

                for key in desired_settings:
                    if key == 'ldap_servers':
                        if key not in current_settings:
                            changes_needed[key] = desired_settings[key]
                        elif len(current_settings[key]) != len(desired_settings[key]):
                            changes_needed[key] = desired_settings[key]
                        else:
                            for i in range(len(desired_settings[key])):
                                if (current_settings[key][i].address != desired_settings[key][i].address or
                                        current_settings[key][i].port != desired_settings[key][i].port):

                                    changes_needed[key] = desired_settings[key]

                    elif key not in current_settings or current_settings[key] != desired_settings[key]:
                        changes_needed[key] = desired_settings[key]

                return changes_needed

            def apply_settings(self, changes_needed: dict, has_existing_cert: bool) -> None:
                """
                Apply the changes needed to the iLO device.

                Args:
                    changes_needed (dict): The changes needed to apply the desired settings.
                """

                if not self.client:
                    self.fail_json(msg='Redfish client is not initialized.')

                account_service_uri: str = self.get_account_service_uri()

                payload: dict = dict()

                if 'local_account_auth_enabled' in changes_needed:
                    payload['LocalAccountAuth'] = 'Enabled' if changes_needed['local_account_auth_enabled'] else 'Disabled'

                ldap: dict = dict()

                if 'state' in changes_needed:
                    if changes_needed['state'] == 'disabled':
                        ldap['ServiceEnabled'] = False
                    elif changes_needed['state'] == 'active_directory':
                        ldap['ServiceEnabled'] = True
                        ldap['AccountProviderType'] = 'ActiveDirectoryService'
                    elif changes_needed['state'] == 'generic_ldap':
                        ldap['ServiceEnabled'] = True
                        ldap['AccountProviderType'] = 'LDAPService'

                if 'ldap_servers' in changes_needed:

                    ldap_servers: List[str] = []

                    for server in changes_needed['ldap_servers']:
                        if server['port'] == 636:
                            ldap_servers.append(server['address'])
                        else:
                            ldap_servers.append(f"{server['address']}:{server['port']}")

                    ldap['ServiceAddresses'] = ldap_servers

                authentication: dict = dict()

                if 'ldap_username' in changes_needed:
                    authentication['Username'] = changes_needed['ldap_username']

                if 'ldap_password' in changes_needed:
                    authentication['Password'] = changes_needed['ldap_password']

                if len(authentication) > 0:
                    ldap['Authentication'] = authentication

                if 'ldap_search_bases' in changes_needed:
                    ldap['LDAPService'] = dict(
                        SearchSettings=dict(
                            BaseDistinguishedNames=changes_needed['ldap_search_bases']
                        )
                    )

                if len(ldap) > 0:
                    payload['LDAP'] = ldap

                if 'use_extended_schema' in changes_needed:

                    if changes_needed['use_extended_schema']:
                        payload['Oem'] = dict(
                            Hpe=dict(
                                DirectorySettings=dict(
                                    LdapAuthenticationMode='ExtendedSchema'
                                )
                            )
                        )
                    else:
                        payload['Oem'] = dict(
                            Hpe=dict(
                                DirectorySettings=dict(
                                    LdapAuthenticationMode='StandardSchema'
                                )
                            )
                        )

                try:
                    response: RestResponse = self.client.patch(account_service_uri, payload)
                except Exception as e:
                    self.handle_error(iLOModuleError('Error applying LDAP settings', exception=to_native(e)))

                if response.status != 200:
                    self.handle_error(iLOModuleError('Failed to apply LDAP settings.'))

                if 'ldap_ca_certificate_serial_number' not in changes_needed:
                    return

                certificates_uri: str = '/redfish/v1/AccountService/ExternalAccountProviders/LDAP/Certificates'
                certificate_uri: str = f'{certificates_uri}/1'

                if has_existing_cert:
                    try:
                        response: RestResponse = self.client.delete(certificate_uri)
                    except Exception as e:
                        self.handle_error(iLOModuleError(f'Error deleting {certificate_uri}', exception=to_native(e)))

                    if response.status != 200:
                        self.handle_error(iLOModuleError(f'Failed to delete {certificate_uri}'))

                ldap_ca_certificate: str = self.params['ldap_ca_certificate'] + '\n'
                payload: dict = dict(CertificateString=ldap_ca_certificate)

                try:
                    response: RestResponse = self.client.post(certificates_uri, payload)
                except Exception as e:
                    self.handle_error(iLOModuleError('Error updating LDAP CA certificate', exception=to_native(e)))

                if response.status != 200:
                    self.handle_error(iLOModuleError('Failed to update LDAP CA certificate'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOAccountSettingsModule = iLOAccountSettingsModule()

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

    state: str = module.params['state']

    if state == 'disabled':
        if module.params.get('local_account_auth_enabled', None) is not None and not module.params['local_account_auth_enabled']:
            module.fail_json(msg='When state is disabled, local_account_auth_enabled must be set to true.')

        module.params['local_account_auth_enabled'] = True

        unsupported_arg_names: list[str] = []

        for arg_name in ['ldap_ca_certificate', 'ldap_servers', 'ldap_username', 'ldap_password', 'ldap_search_bases']:
            if module.params.get(arg_name, None) is not None:
                unsupported_arg_names.append(arg_name)

        if len(unsupported_arg_names) > 0:
            module.fail_json(
                msg=f'When state is disabled, the following arguments must not be provided: {", ".join(unsupported_arg_names)}'
            )

    ldap_ca_certificate: Optional[str] = module.params.get('ldap_ca_certificate', None)

    if ldap_ca_certificate is not None:

        module.params['ldap_ca_certificate'] = ldap_ca_certificate.strip(' \n\r\t')
        ldap_ca_certificate = module.params['ldap_ca_certificate']

        try:
            ca_cert: x509.Certificate = x509.load_pem_x509_certificate(ldap_ca_certificate.encode(), default_backend())
        except Exception as e:
            module.fail_json(msg='Failed to parse LDAP CA certificate', exception=traceback.format_exc())

        ca_cert_serial_number: str = hex(ca_cert.serial_number)[2:].upper()

    desired_settings: dict = module.get_desired_settings()

    if desired_settings['state'] != 'disabled':
        desired_settings['ldap_ca_certificate_serial_number'] = ca_cert_serial_number

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    current_settings: dict = module.get_current_settings()

    result['diff']['before'] = current_settings.copy()

    changes_needed: dict = module.get_changes_needed(current_settings, desired_settings)
    update_password: str = module.params['update_password']

    changes_length_to_apply: int = 1 if update_password == 'when_changed' else 0

    if len(changes_needed) > changes_length_to_apply:

        result['changed'] = True

        after_settings: dict = desired_settings.copy()
        returned_settings: dict = desired_settings.copy()

        if 'ldap_password' in desired_settings:
            after_settings['ldap_password'] = '*'
            del returned_settings['ldap_password']

        result['diff']['after'] = after_settings
        result.update(returned_settings)

        if not module.check_mode:
            module.apply_settings(changes_needed, current_settings.get('ldap_ca_certificate_serial_number', None) is not None)

    else:
        result['diff']['after'] = current_settings.copy()
        result.update(changes_needed)

    module.logout()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
