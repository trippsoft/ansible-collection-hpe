#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_hostname
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures iLO hostname.
description:
  - >-
    This module configures the hostname for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  hostname:
    type: str
    required: true
    description:
      - The hostname to configure for the iLO device.
"""

EXAMPLES = r"""
- name: Configure iLO hostname
  trippsc2.hpe.ilo_hostname:
    hostname: "ilo-hostname"
"""

RETURN = r"""
hostname:
  type: str
  returned: always
  description:
    - The configured hostname for the iLO device.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError
from ..module_utils.ilo_utils import validate_hostname

from typing import Optional

ARGSPEC: dict = dict(
    hostname=dict(type='str', required=True)
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    # Stub class to allow ansible-test to run without Redfish
    class iLOHostnameModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO hostname modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, argument_spec=ARGSPEC.copy(), supports_check_mode=True, **kwargs)

        def get_hostname(self) -> str:
            """
            Get the hostname from the Redfish client.

            Returns:
                str: The hostname.
            """

            pass

        def set_hostname(self, hostname: str) -> None:
            """
            Set the manager Ethernet hostname in the Redfish client.

            Args:
                hostname (str): The hostname to set.
            """

            _ = hostname
            pass

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOHostnameModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO hostname modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, argument_spec=ARGSPEC.copy(), supports_check_mode=True, **kwargs)

        def get_hostname(self) -> str:
            """
            Get the hostname from the Redfish client.

            Returns:
                str: The hostname.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_ethernet_uri: str = self.get_manager_ethernet_uri()

            try:
                response: RestResponse = self.client.get(manager_ethernet_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error retrieving manager Ethernet hostname', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message='Failed to retrieve manager Ethernet hostname'))

            if 'HostName' not in response.dict:
                self.handle_error(iLOModuleError(message='No HostName found in manager Ethernet'))

            return response.dict['HostName']

        def set_hostname(self, hostname: str) -> None:
            """
            Set the manager Ethernet hostname in the Redfish client.

            Args:
                hostname (str): The hostname to set.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_ethernet_uri: str = self.get_manager_ethernet_uri()

            payload: dict = dict(HostName=hostname)

            try:
                response: RestResponse = self.client.patch(manager_ethernet_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error setting manager Ethernet hostname', exception=to_native(e)))

            if response.status not in [200, 204]:
                self.handle_error(iLOModuleError(message='Failed to set manager Ethernet hostname'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOHostnameModule = iLOHostnameModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    hostname: str = module.params['hostname']

    if not validate_hostname(hostname):
        module.fail_json(
            msg='Invalid hostname format.  ' +
              'The hostname must be a valid DNS name, which can only include letters, numbers, and hyphens, and must not exceed 63 characters in length.'
            )

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    current_hostname: str = module.get_hostname()

    result["diff"]["before"]["hostname"] = current_hostname
    result["diff"]["after"]["hostname"] = hostname
    result["hostname"] = hostname

    if current_hostname != hostname:

        if not module.check_mode:
            module.set_hostname(hostname)

        result["changed"] = True

    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
