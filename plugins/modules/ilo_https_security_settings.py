#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_https_security_settings
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures iLO HTTPS security settings
description:
  - >-
    This module configures the HTTPS settings for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  disable_weak_ciphers:
    type: bool
    required: false
    description:
      - Whether to disable weak ciphers on the iLO device.
  security_state:
    type: str
    required: false
    choices:
      - production
      - high_security
      - fips
    description:
      - The security state to configure for the iLO device.
  tlsv1_0_enabled:
    type: bool
    required: false
    description:
      - Whether to enable TLSv1.0 on the iLO device.
  tlsv1_1_enabled:
    type: bool
    required: false
    description:
      - Whether to enable TLSv1.1 on the iLO device.
  tlsv1_2_enabled:
    type: bool
    required: false
    description:
      - Whether to enable TLSv1.2 on the iLO device.
  tlsv1_3_enabled:
    type: bool
    required: false
    description:
      - Whether to enable TLSv1.3 on the iLO device.
"""

EXAMPLES = r"""
- name: Configure iLO hostname
  trippsc2.hpe.ilo_hostname:
    base_url: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    disable_weak_ciphers: true
    security_state: 'production'
    tlsv1_0_enabled: false
    tlsv1_1_enabled: false
    tlsv1_2_enabled: true
    tlsv1_3_enabled: true
"""

RETURN = r"""
disable_weak_ciphers:
  type: bool
  returned: always
  description:
    - Whether weak ciphers are disabled on the iLO device.
security_state:
  type: str
  returned: always
  description:
    - The configured security state for the iLO device.
tlsv1_0_enabled:
  type: bool
  returned: always
  description:
    - Whether TLSv1.0 is enabled on the iLO device.
tlsv1_1_enabled:
  type: bool
  returned: always
  description:
    - Whether TLSv1.1 is enabled on the iLO device.
tlsv1_2_enabled:
  type: bool
  returned: always
  description:
    - Whether TLSv1.2 is enabled on the iLO device.
tlsv1_3_enabled:
  type: bool
  returned: always
  description:
    - Whether TLSv1.3 is enabled on the iLO device.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError
from typing import Optional

MODULE_INIT_ARGS: dict = dict(
    argument_spec=dict(
        disable_weak_ciphers=dict(type='bool', required=False),
        security_state=dict(type='str', required=False, choices=['production', 'high_security', 'fips']),
        tlsv1_0_enabled=dict(type='bool', required=False),
        tlsv1_1_enabled=dict(type='bool', required=False),
        tlsv1_2_enabled=dict(type='bool', required=False),
        tlsv1_3_enabled=dict(type='bool', required=False)
    ),
    required_one_of=[
        (
            'disable_weak_ciphers',
            'security_state',
            'tlsv1_0_enabled',
            'tlsv1_1_enabled',
            'tlsv1_2_enabled',
            'tlsv1_3_enabled'
        )
    ],
    supports_check_mode=True
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    class iLOHttpsSecuritySettingsModule(iLOModule):
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

        def apply_settings(self, changes_needed: dict) -> None:
            """
            Apply the changes needed to the iLO device.

            Args:
                changes_needed (dict): The changes needed to apply the desired settings.
            """

            discard = changes_needed

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOHttpsSecuritySettingsModule(iLOModule):
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

            if self.params.get('disable_weak_ciphers', None) is not None:
                desired_settings['disable_weak_ciphers'] = self.params['disable_weak_ciphers']

            if self.params.get('security_state', None) is not None:
                desired_settings['security_state'] = self.params['security_state']

            if self.params.get('tlsv1_0_enabled', None) is not None:
                desired_settings['tlsv1_0_enabled'] = self.params['tlsv1_0_enabled']

            if self.params.get('tlsv1_1_enabled', None) is not None:
                desired_settings['tlsv1_1_enabled'] = self.params['tlsv1_1_enabled']

            if self.params.get('tlsv1_2_enabled', None) is not None:
                desired_settings['tlsv1_2_enabled'] = self.params['tlsv1_2_enabled']

            if self.params.get('tlsv1_3_enabled', None) is not None:
                desired_settings['tlsv1_3_enabled'] = self.params['tlsv1_3_enabled']

            return desired_settings

        def get_current_settings(self) -> dict:
            """
            Get the current security settings from the iLO device.

            Returns:
                dict: The current security settings.
            """

            security_settings_uri = self.get_manager_security_service_uri()

            try:
                response: RestResponse = self.client.get(security_settings_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(f'Error retrieving {security_settings_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(f'Failed to retrieve {security_settings_uri}'))

            if 'DisableWeakCiphers' not in response.dict:
                self.handle_error(iLOModuleError(f"'DisableWeakCiphers' not found in {security_settings_uri}"))

            disable_weak_ciphers: bool = response.dict['DisableWeakCiphers']

            if 'SecurityState' not in response.dict:
                self.handle_error(iLOModuleError(f"'SecurityState' not found in {security_settings_uri}"))

            security_state: str = response.dict['SecurityState']

            if security_state == 'HighSecurity':
                security_state = 'high_security'
            else:
                security_state = security_state.lower()

            if 'TLSVersion' not in response.dict:
                self.handle_error(iLOModuleError(f"'TLSVersion' not found in {security_settings_uri}"))

            tls_version: dict = response.dict['TLSVersion']

            if 'TLS1_0' not in tls_version:
                self.handle_error(iLOModuleError(f"'TLS1_0' not found in {security_settings_uri}"))

            tlsv1_0_enabled: bool = tls_version['TLS1_0'] == 'Enabled'

            if 'TLS1_1' not in tls_version:
                self.handle_error(iLOModuleError(f"'TLS1_1' not found in {security_settings_uri}"))

            tlsv1_1_enabled: bool = tls_version['TLS1_1'] == 'Enabled'

            if 'TLS1_2' not in tls_version:
                self.handle_error(iLOModuleError(f"'TLS1_2' not found in {security_settings_uri}"))

            tlsv1_2_enabled: bool = tls_version['TLS1_2'] == 'Enabled'

            if 'TLS1_3' not in tls_version:
                self.handle_error(iLOModuleError(f"'TLS1_3' not found in {security_settings_uri}"))

            tlsv1_3_enabled: bool = tls_version['TLS1_3'] == 'Enabled'

            return dict(
                disable_weak_ciphers=disable_weak_ciphers,
                security_state=security_state,
                tlsv1_0_enabled=tlsv1_0_enabled,
                tlsv1_1_enabled=tlsv1_1_enabled,
                tlsv1_2_enabled=tlsv1_2_enabled,
                tlsv1_3_enabled=tlsv1_3_enabled
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
                if key not in current_settings or current_settings[key] != desired_settings[key]:
                    changes_needed[key] = desired_settings[key]

            return changes_needed

        def apply_settings(self, changes_needed: dict) -> None:
            """
            Apply the changes needed to the iLO device.

            Args:
                changes_needed (dict): The changes needed to apply the desired settings.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized.')

            security_settings_uri = self.get_manager_security_service_uri()

            payload: dict = dict()

            if 'disable_weak_ciphers' in changes_needed:
                payload['DisableWeakCiphers'] = changes_needed['disable_weak_ciphers']

            if 'security_state' in changes_needed:
                if changes_needed['security_state'] == 'high_security':
                    payload['SecurityState'] = 'HighSecurity'
                elif changes_needed['security_state'] == 'fips':
                    payload['SecurityState'] = 'FIPS'
                else:
                    payload['SecurityState'] = 'Production'

            tls_version: dict = dict()

            if 'tlsv1_0_enabled' in changes_needed:
                tls_version['TLS1_0'] = 'Enabled' if changes_needed['tlsv1_0_enabled'] else 'Disabled'

            if 'tlsv1_1_enabled' in changes_needed:
                tls_version['TLS1_1'] = 'Enabled' if changes_needed['tlsv1_1_enabled'] else 'Disabled'

            if 'tlsv1_2_enabled' in changes_needed:
                tls_version['TLS1_2'] = 'Enabled' if changes_needed['tlsv1_2_enabled'] else 'Disabled'

            if 'tlsv1_3_enabled' in changes_needed:
                tls_version['TLS1_3'] = 'Enabled' if changes_needed['tlsv1_3_enabled'] else 'Disabled'

            if len(tls_version) > 0:
                payload['TLSVersion'] = tls_version

            try:
                response: RestResponse = self.client.patch(security_settings_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError('Error applying security settings', exception=to_native(e)))

            if response.status not in [200, 201, 204]:
                self.handle_error(iLOModuleError('Failed to apply security settings'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOHttpsSecuritySettingsModule = iLOHttpsSecuritySettingsModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    desired_settings: dict = module.get_desired_settings()

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    current_settings: dict = module.get_current_settings()

    result['diff']['before'] = current_settings

    changes_needed: dict = module.get_changes_needed(current_settings, desired_settings)

    if len(changes_needed) > 0:
        result['changed'] = True
        result['diff']['after'] = desired_settings.copy()
        result.update(desired_settings)

        if not module.check_mode:
            module.apply_settings(changes_needed)

    else:
        result['diff']['after'] = current_settings.copy()
        result.update(current_settings)

    module.logout()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
