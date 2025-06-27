#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_account_settings
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configure iLO account settings
description:
  - >-
    This module configures the account settings for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  auth_failure_delay_time:
    type: int
    required: false
    description:
      - The delay time in seconds before an account is locked after a failed authentication attempt.
  auth_failure_logging_threshold:
    type: int
    required: false
    description:
      - The number of failed authentication attempts before the account is locked.
  auth_failures_before_delay:
    type: int
    required: false
    description:
      - The number of failed authentication attempts before a delay is applied.
  enforce_password_complexity:
    type: bool
    required: false
    description:
      - Whether to enforce password complexity requirements on the iLO device.
  http_basic_auth:
    type: str
    required: false
    choices:
      - enabled
      - unadvertised
      - disabled
    description:
      - The HTTP Basic Authentication setting for the iLO device.
      - If set to V(enabled), HTTP Basic Authentication is enabled and advertised by the C(WWW-Authenticate) header.
      - If set to V(unadvertised), HTTP Basic Authentication is enabled but not advertised by the C(WWW-Authenticate) header.
      - If set to V(disabled), HTTP Basic Authentication is disabled.
  min_password_length:
    type: int
    required: false
    description:
      - The minimum password length for accounts on the iLO device.
"""

EXAMPLES = r"""
- name: Configure iLO account settings
  trippsc2.hpe.ilo_account_settings:
    base_url: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    auth_failure_delay_time: 30
    auth_failure_logging_threshold: 5
    auth_failures_before_delay: 3
    enforce_password_complexity: true
    http_basic_auth: 'enabled'
    min_password_length: 12
"""

RETURN = r"""
auth_failure_delay_time:
  type: int
  returned: always
  description:
    - The delay time in seconds before an account is locked after a failed authentication attempt.
auth_failure_logging_threshold:
  type: int
  returned: always
  description:
    - The number of failed authentication attempts before the account is locked.
auth_failures_before_delay:
  type: int
  returned: always
  description:
    - The number of failed authentication attempts before a delay is applied.
enforce_password_complexity:
  type: bool
  returned: always
  description:
    - Whether to enforce password complexity requirements on the iLO device.
http_basic_auth:
  type: str
  returned: always
  description:
    - The HTTP Basic Authentication setting for the iLO device.
    - Possible values are V(enabled), V(unadvertised), and V(disabled).
min_password_length:
  type: int
  returned: always
  description:
    - The minimum password length for accounts on the iLO device.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError

from typing import Optional

MODULE_INIT_ARGS: dict = dict(
    argument_spec=dict(
        auth_failure_delay_time=dict(type='int', required=False),
        auth_failure_logging_threshold=dict(type='int', required=False),
        auth_failures_before_delay=dict(type='int', required=False),
        enforce_password_complexity=dict(type='bool', required=False),
        http_basic_auth=dict(type='str', required=False, choices=['enabled', 'unadvertised', 'disabled']),
        min_password_length=dict(type='int', required=False, no_log=False)
    ),
    required_one_of=[
        (
            'auth_failure_delay_time',
            'auth_failure_logging_threshold',
            'auth_failures_before_delay',
            'enforce_password_complexity',
            'http_basic_auth',
            'min_password_length'
        )
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

            if self.params.get('auth_failure_delay_time') is not None:
                desired_settings['auth_failure_delay_time'] = self.params['auth_failure_delay_time']

            if self.params.get('auth_failure_logging_threshold') is not None:
                desired_settings['auth_failure_logging_threshold'] = self.params['auth_failure_logging_threshold']

            if self.params.get('auth_failures_before_delay') is not None:
                desired_settings['auth_failures_before_delay'] = self.params['auth_failures_before_delay']

            if self.params.get('enforce_password_complexity') is not None:
                desired_settings['enforce_password_complexity'] = self.params['enforce_password_complexity']

            if self.params.get('http_basic_auth') is not None:
                desired_settings['http_basic_auth'] = self.params['http_basic_auth']

            if self.params.get('min_password_length') is not None:
                desired_settings['min_password_length'] = self.params['min_password_length']

            return desired_settings

        def get_current_settings(self) -> dict:
            """
            Get the current security settings from the iLO device.

            Returns:
                dict: The current security settings.
            """

            account_service_uri = self.get_account_service_uri()

            try:
                response: RestResponse = self.client.get(account_service_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(f'Error retrieving {account_service_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(f'Failed to retrieve {account_service_uri}'))

            if 'HTTPBasicAuth' not in response.dict:
                self.handle_error(iLOModuleError(f'\'HTTPBasicAuth\' not found in {account_service_uri}'))

            http_basic_auth: str = response.dict['HTTPBasicAuth'].lower()

            if 'MinPasswordLength' not in response.dict:
                self.handle_error(iLOModuleError(f'\'MinPasswordLength\' not found in {account_service_uri}'))

            min_password_length: int = response.dict['MinPasswordLength']

            if 'Oem' not in response.dict:
                self.handle_error(iLOModuleError(f'\'Oem\' not found in {account_service_uri}'))

            oem: dict = response.dict['Oem']

            if 'Hpe' not in oem:
                self.handle_error(iLOModuleError(f'\'Oem.Hpe\' not found in {account_service_uri}'))

            hpe: dict = oem['Hpe']

            if 'AuthFailureDelayTimeSeconds' not in hpe:
                self.handle_error(iLOModuleError(f'\'Oem.Hpe.AuthFailureDelayTimeSeconds\' not found in {account_service_uri}'))

            auth_failure_delay_time: int = hpe['AuthFailureDelayTimeSeconds']

            if 'AuthFailureLoggingThreshold' not in hpe:
                self.handle_error(iLOModuleError(f'\'Oem.Hpe.AuthFailureLoggingThreshold\' not found in {account_service_uri}'))

            auth_failure_logging_threshold: int = hpe['AuthFailureLoggingThreshold']

            if 'AuthFailuresBeforeDelay' not in hpe:
                self.handle_error(iLOModuleError(f'\'Oem.Hpe.AuthFailuresBeforeDelay\' not found in {account_service_uri}'))

            auth_failures_before_delay: int = hpe['AuthFailuresBeforeDelay']

            if 'EnforcePasswordComplexity' not in hpe:
                self.handle_error(iLOModuleError(f'\'Oem.Hpe.EnforcePasswordComplexity\' not found in {account_service_uri}'))

            enforce_password_complexity: bool = hpe['EnforcePasswordComplexity']

            return dict(
                auth_failure_delay_time=auth_failure_delay_time,
                auth_failure_logging_threshold=auth_failure_logging_threshold,
                auth_failures_before_delay=auth_failures_before_delay,
                enforce_password_complexity=enforce_password_complexity,
                http_basic_auth=http_basic_auth,
                min_password_length=min_password_length
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

            account_service_uri: str = self.get_account_service_uri()

            payload: dict = dict()
            oem: dict = dict(Hpe=dict())

            if 'auth_failure_delay_time' in changes_needed:
                oem['Hpe']['AuthFailureDelayTimeSeconds'] = changes_needed['auth_failure_delay_time']

            if 'auth_failure_logging_threshold' in changes_needed:
                oem['Hpe']['AuthFailureLoggingThreshold'] = changes_needed['auth_failure_logging_threshold']

            if 'auth_failures_before_delay' in changes_needed:
                oem['Hpe']['AuthFailuresBeforeDelay'] = changes_needed['auth_failures_before_delay']

            if 'enforce_password_complexity' in changes_needed:
                oem['Hpe']['EnforcePasswordComplexity'] = changes_needed['enforce_password_complexity']

            if 'http_basic_auth' in changes_needed:
                if changes_needed['http_basic_auth'] == 'enabled':
                    payload['HTTPBasicAuth'] = 'Enabled'
                elif changes_needed['http_basic_auth'] == 'unadvertised':
                    payload['HTTPBasicAuth'] = 'Unadvertised'
                elif changes_needed['http_basic_auth'] == 'disabled':
                    payload['HTTPBasicAuth'] = 'Disabled'

            if 'min_password_length' in changes_needed:
                payload['MinPasswordLength'] = changes_needed['min_password_length']

            if len(oem['Hpe']) > 0:
                payload['Oem'] = oem

            try:
                response: RestResponse = self.client.patch(account_service_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError('Error applying security settings', exception=to_native(e)))

            if response.status not in [200, 201, 204]:
                self.handle_error(iLOModuleError('Failed to apply security settings'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOAccountSettingsModule = iLOAccountSettingsModule()

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
