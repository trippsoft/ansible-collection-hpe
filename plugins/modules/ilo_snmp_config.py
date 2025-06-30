#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_snmp_config
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures iLO SNMP settings
description:
  - >-
    This module configures the SNMP settings for an HPE iLO device.  This module only configures general SNMP settings.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  enabled:
    type: bool
    required: false
    description:
      - Whether SNMP is enabled on the iLO device.
      - This supersedes all other SNMP settings on the iLO device.
  alerts_enabled:
    type: bool
    required: false
    description:
      - Whether SNMP alerts are enabled on the iLO device.
  contact:
    type: str
    required: false
    description:
      - The contact information for the SNMP configuration.
  location:
    type: str
    required: false
    description:
      - The location information for the SNMP configuration.
  role:
    type: str
    required: false
    description:
      - The system role information for the SNMP configuration.
  role_detail:
    type: str
    required: false
    description:
      - The system role detail information for the SNMP configuration.
  snmpv1_enabled:
    type: bool
    required: false
    description:
      - Whether SNMPv1 is enabled on the iLO device.
      - This supersedes all other SNMPv1 settings on the iLO device.
  snmpv1_requests_enabled:
    type: bool
    required: false
    description:
      - Whether SNMPv1 requests are enabled on the iLO device.
  snmpv1_trap_enabled:
    type: bool
    required: false
    description:
      - Whether SNMPv1 traps are enabled on the iLO device.
  snmpv3_inform_retry_attempts:
    type: int
    required: false
    description:
      - The number of retry attempts for SNMPv3 informs.
  snmpv3_inform_retry_interval:
    type: int
    required: false
    description:
      - The interval in seconds between SNMPv3 inform retry attempts in seconds.
  snmpv3_requests_enabled:
    type: bool
    required: false
    description:
      - Whether SNMPv3 requests are enabled on the iLO device.
  snmpv3_trap_enabled:
    type: bool
    required: false
    description:
      - Whether SNMPv3 traps are enabled on the iLO device.
  trap_source_hostname:
    type: str
    required: false
    choices:
      - 'ilo'
      - 'host'
    description:
        - The source hostname for SNMP traps.
        - If set to V(ilo), the iLO hostname will be used.
        - If set to V(host), the host's hostname will be used.
"""

EXAMPLES = r"""
- name: Disable iLO SNMP
  trippsc2.hpe.ilo_snmp_config:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    enabled: false

- name: Disable iLO SNMPv1
  trippsc2.hpe.ilo_snmp_config:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    snmpv1_enabled: false

- name: Configure iLO SNMP with all settings
  trippsc2.hpe.ilo_snmp_config:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    enabled: true
    alerts_enabled: true
    contact: 'John Doe'
    location: 'Data Center 1'
    role: 'Database Server'
    role_detail: 'Primary Database'
    snmpv1_enabled: true
    snmpv1_requests_enabled: true
    snmpv1_trap_enabled: true
    snmpv3_inform_retry_attempts: 2
    snmpv3_inform_retry_interval: 10
    snmpv3_requests_enabled: true
    snmpv3_trap_enabled: true
    trap_source_hostname: 'ilo'
"""

RETURN = r"""
enabled:
  type: bool
  returned: always
  description:
    - Whether SNMP is enabled on the iLO device.
alerts_enabled:
  type: bool
  returned: always
  description:
    - Whether SNMP alerts are enabled on the iLO device.
contact:
  type: str
  returned: always
  description:
    - The contact information for the SNMP configuration.
location:
  type: str
  returned: always
  description:
    - The location information for the SNMP configuration.
role:
  type: str
  returned: always
  description:
    - The system role information for the SNMP configuration.
role_detail:
  type: str
  returned: always
  description:
    - The system role detail information for the SNMP configuration.
snmpv1_enabled:
  type: bool
  returned: always
  description:
    - Whether SNMPv1 is enabled on the iLO device.
snmpv1_requests_enabled:
  type: bool
  returned: always and O(snmpv1_enabled=true)
  description:
    - Whether SNMPv1 requests are enabled on the iLO device.
snmpv1_trap_enabled:
  type: bool
  returned: always and O(snmpv1_enabled=true)
  description:
    - Whether SNMPv1 traps are enabled on the iLO device.
snmpv3_inform_retry_attempts:
  type: int
  returned: always
  description:
    - The number of retry attempts for SNMPv3 informs.
snmpv3_inform_retry_interval:
  type: int
  returned: always
  description:
    - The interval in seconds between SNMPv3 inform retry attempts.
snmpv3_requests_enabled:
  type: bool
  returned: always
  description:
    - Whether SNMPv3 requests are enabled on the iLO device.
snmpv3_trap_enabled:
  type: bool
  returned: always
  description:
    - Whether SNMPv3 traps are enabled on the iLO device.
trap_source_hostname:
  type: str
  returned: always
  description:
    - The source hostname for SNMP traps.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import COMMON_ARGSPEC, iLOModule
from ..module_utils.ilo_module_error import iLOModuleError

from typing import Optional

MODULE_INIT_ARGS: dict = dict(
    argument_spec=dict(
        enabled=dict(type='bool', required=False),
        alerts_enabled=dict(type='bool', required=False),
        contact=dict(type='str', required=False),
        location=dict(type='str', required=False),
        role=dict(type='str', required=False),
        role_detail=dict(type='str', required=False),
        snmpv1_enabled=dict(type='bool', required=False),
        snmpv1_requests_enabled=dict(type='bool', required=False),
        snmpv1_trap_enabled=dict(type='bool', required=False),
        snmpv3_inform_retry_attempts=dict(type='int', required=False),
        snmpv3_inform_retry_interval=dict(type='int', required=False),
        snmpv3_requests_enabled=dict(type='bool', required=False),
        snmpv3_trap_enabled=dict(type='bool', required=False),
        trap_source_hostname=dict(type='str', required=False, choices=['ilo', 'host'])
    ),
    required_one_of=[
        (
            'enabled',
            'alerts_enabled',
            'contact',
            'location',
            'role',
            'role_detail',
            'snmpv1_enabled',
            'snmpv1_requests_enabled',
            'snmpv1_trap_enabled',
            'snmpv3_inform_retry_attempts',
            'snmpv3_inform_retry_interval',
            'snmpv3_requests_enabled',
            'snmpv3_trap_enabled',
            'trap_source_hostname'
        )
    ],
    supports_check_mode=True
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    class iLOSnmpConfigModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO SNMP configuration modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

        def get_desired_config(self) -> dict:
            """
            Get the desired SNMP configuration from the module parameters.

            Returns:
                dict: The desired SNMP configuration.
            """

            pass

        def get_snmp_config(self) -> dict:
            """
            Get the SNMP configuration from the Redfish client.

            Returns:
                dict: The SNMP configuration data.
            """

            pass

        def get_changes_needed(self, current: dict, desired: dict) -> dict:
            """
            Get the changes needed between the current and desired SNMP configuration.

            Args:
                current (dict): The current SNMP configuration.
                desired (dict): The desired SNMP configuration.

            Returns:
                dict: A dictionary of changes needed.
            """

            discard = current
            discard = desired
            pass

        def set_snmp_config(self, changes_needed: dict) -> None:
            """
            Set the SNMP configuration in the Redfish client.

            Args:
                changes_needed (dict): The changes needed to the SNMP configuration.
            """

            discard = changes_needed
            pass

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOSnmpConfigModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO SNMP configuration modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

        def get_desired_config(self) -> dict:
            """
            Get the desired SNMP configuration from the module parameters.

            Returns:
                dict: The desired SNMP configuration.
            """

            desired_config: dict = self.params.copy()

            if 'state' in desired_config:
                del desired_config['state']

            for key in MODULE_INIT_ARGS['argument_spec'].keys():
                if desired_config[key] is None:
                    del desired_config[key]

            for key in COMMON_ARGSPEC.keys():
                if key in desired_config:
                    del desired_config[key]

            return desired_config

        def get_snmp_config(self) -> dict:
            """
            Get the SNMP configuration from the Redfish client.

            Returns:
                dict: The SNMP configuration data.
            """

            snmp_service_uri: str = self.get_manager_snmp_service_uri()

            try:
                response: RestResponse = self.client.get(snmp_service_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Failed retrieving {snmp_service_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed retrieving {snmp_service_uri}'))

            if 'Status' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Status\' not found in {snmp_service_uri}'))

            status: dict = response.dict['Status']

            if 'State' not in status:
                self.handle_error(iLOModuleError(message=f'\'Status.State\' not found in {snmp_service_uri}'))

            enabled: bool = status['State'].lower() == 'enabled'

            if 'AlertsEnabled' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'AlertsEnabled\' not found in {snmp_service_uri}'))

            alerts_enabled: bool = response.dict['AlertsEnabled']

            if 'Contact' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Contact\' not found in {snmp_service_uri}'))

            contact: str = response.dict['Contact']

            if 'Location' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Location\' not found in {snmp_service_uri}'))

            location: str = response.dict['Location']

            if 'Role' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Role\' not found in {snmp_service_uri}'))

            role: str = response.dict['Role']

            if 'RoleDetail' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'RoleDetail\' not found in {snmp_service_uri}'))

            role_detail: str = response.dict['RoleDetail']

            if 'SNMPv1Enabled' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'SNMPv1Enabled\' not found in {snmp_service_uri}'))

            snmpv1_enabled: bool = response.dict['SNMPv1Enabled']

            if 'SNMPv1RequestsEnabled' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'SNMPv1RequestsEnabled\' not found in {snmp_service_uri}'))

            snmpv1_requests_enabled: bool = response.dict['SNMPv1RequestsEnabled']

            if 'SNMPv1TrapEnabled' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'SNMPv1TrapEnabled\' not found in {snmp_service_uri}'))

            snmpv1_trap_enabled: bool = response.dict['SNMPv1TrapEnabled']

            if 'SNMPv3InformRetryAttempt' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'SNMPv3InformRetryAttempt\' not found in {snmp_service_uri}'))

            snmpv3_inform_retry_attempts: int = response.dict['SNMPv3InformRetryAttempt']

            if 'SNMPv3InformRetryIntervalSeconds' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'SNMPv3InformRetryIntervalSeconds\' not found in {snmp_service_uri}'))

            snmpv3_inform_retry_interval: int = response.dict['SNMPv3InformRetryIntervalSeconds']

            if 'SNMPv3RequestsEnabled' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'SNMPv3RequestsEnabled\' not found in {snmp_service_uri}'))

            snmpv3_requests_enabled: bool = response.dict['SNMPv3RequestsEnabled']

            if 'SNMPv3TrapEnabled' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'SNMPv3TrapEnabled\' not found in {snmp_service_uri}'))

            snmpv3_trap_enabled: bool = response.dict['SNMPv3TrapEnabled']

            if 'TrapSourceHostname' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'TrapSourceHostname\' not found in {snmp_service_uri}'))

            if response.dict['TrapSourceHostname'] == 'System':
                trap_source_hostname: str = 'host'
            elif response.dict['TrapSourceHostname'] == 'Manager':
                trap_source_hostname: str = 'ilo'
            else:
                self.handle_error(iLOModuleError(message=f'\'TrapSourceHostname\' is invalid in {snmp_service_uri}'))

            return dict(
                enabled=enabled,
                alerts_enabled=alerts_enabled,
                contact=contact,
                location=location,
                role=role,
                role_detail=role_detail,
                snmpv1_enabled=snmpv1_enabled,
                snmpv1_requests_enabled=snmpv1_requests_enabled,
                snmpv1_trap_enabled=snmpv1_trap_enabled,
                snmpv3_inform_retry_attempts=snmpv3_inform_retry_attempts,
                snmpv3_inform_retry_interval=snmpv3_inform_retry_interval,
                snmpv3_requests_enabled=snmpv3_requests_enabled,
                snmpv3_trap_enabled=snmpv3_trap_enabled,
                trap_source_hostname=trap_source_hostname
            )

        def get_changes_needed(self, current: dict, desired: dict) -> dict:
            """
            Get the changes needed between the current and desired SNMP configuration.

            Args:
                current (dict): The current SNMP configuration.
                desired (dict): The desired SNMP configuration.

            Returns:
                dict: A dictionary of changes needed.
            """
            changes_needed: dict = dict()

            for key in desired:
                if key not in current or current[key] != desired[key]:
                    changes_needed[key] = desired[key]

            return changes_needed

        def set_snmp_config(self, changes_needed: dict) -> None:
            """
            Set the SNMP configuration in the Redfish client.

            Args:
                changes_needed (dict): The changes needed to the SNMP configuration.
            """

            snmp_service_uri: str = self.get_manager_snmp_service_uri()

            payload: dict = dict()

            for key, value in changes_needed.items():
                if key == 'enabled':
                    payload['Status'] = dict(State='Enabled' if value else 'Disabled')
                elif key == 'alerts_enabled':
                    payload['AlertsEnabled'] = value
                elif key == 'contact':
                    payload['Contact'] = value
                elif key == 'location':
                    payload['Location'] = value
                elif key == 'role':
                    payload['Role'] = value
                elif key == 'role_detail':
                    payload['RoleDetail'] = value
                elif key == 'snmpv1_enabled':
                    payload['SNMPv1Enabled'] = value
                elif key == 'snmpv1_requests_enabled':
                    payload['SNMPv1RequestsEnabled'] = value
                elif key == 'snmpv1_trap_enabled':
                    payload['SNMPv1TrapEnabled'] = value
                elif key == 'snmpv3_inform_retry_attempts':
                    payload['SNMPv3InformRetryAttempt'] = value
                elif key == 'snmpv3_inform_retry_interval':
                    payload['SNMPv3InformRetryIntervalSeconds'] = value
                elif key == 'snmpv3_requests_enabled':
                    payload['SNMPv3RequestsEnabled'] = value
                elif key == 'snmpv3_trap_enabled':
                    payload['SNMPv3TrapEnabled'] = value
                elif key == 'trap_source_hostname':
                    if value == 'ilo':
                        payload['TrapSourceHostname'] = 'Manager'
                    elif value == 'host':
                        payload['TrapSourceHostname'] = 'System'

            try:
                response: RestResponse = self.client.patch(snmp_service_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error occurred when configuring SNMP', exception=to_native(e)))

            if response.status not in [200, 204]:
                self.handle_error(iLOModuleError(message='Failed to configure SNMP'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOSnmpConfigModule = iLOSnmpConfigModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    desired_config: dict = module.get_desired_config()

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    current_config: dict = module.get_snmp_config()

    result["diff"]["before"] = current_config.copy()

    changes_needed: dict = module.get_changes_needed(current_config, desired_config)

    if len(changes_needed) == 0:

        result["diff"]["after"] = current_config.copy()
        result.update(current_config)

    else:

        result['changed'] = True
        result["diff"]["after"] = current_config.copy()
        result["diff"]["after"].update(changes_needed)
        result.update(result["diff"]["after"])

        if not module.check_mode:
            module.set_snmp_config(changes_needed)

    module.logout()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
