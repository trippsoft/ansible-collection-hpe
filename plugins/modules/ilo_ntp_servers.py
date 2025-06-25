#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_ntp_servers
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures iLO IPv4 NTP servers.
description:
  - >-
    This module configures the IPv4 NTP servers for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  ntp_servers:
    type: list
    required: false
    elements: str
    description:
      - The list of IPv4 NTP servers to configure.
      - Each server should be specified as a string in dotted-decimal notation (e.g., "192.0.2.1").
      - The list must contain no more than three servers.
  use_dhcp:
    type: bool
    required: false
    description:
      - Whether to use DHCP for NTP server configuration.
      - If set to true, the NTP servers will be obtained via DHCP.
      - If set to false, the NTP servers will be configured manually.
      - If O(ntp_servers) is provided, this option will default to V(false).
      - If O(ntp_servers) is not provided, this option will default to V(true).
      - If O(ntp_servers) is provided and this is V(true), the module will fail.
"""

EXAMPLES = r"""
- name: Configure iLO IPv4 NTP servers
  trippsc2.hpe.ilo_ntp_servers:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    ntp_servers:
      - "192.0.2.1"
      - "192.0.2.2"
      - "192.0.2.3"

- name: Configure iLO IPv4 NTP servers using DHCP
  trippsc2.hpe.ilo_ntp_servers:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    use_dhcp: true
"""

RETURN = r"""
ntp_servers:
  type: list
  returned: |
    O(ntp_servers) is provided
  elements: str
  description:
    - The list of configured IPv4 NTP servers.
use_dhcp:
  type: bool
  returned: always
  description:
    - Whether DHCP is used for NTP server configuration.
    - If true, the NTP servers are obtained via DHCP.
    - If false, the NTP servers are configured manually.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError
from ..module_utils.ilo_utils import validate_ipv4, validate_ipv6

from typing import List, Optional

ARGSPEC: dict = dict(
    ntp_servers=dict(type='list', required=False, elements='str'),
    use_dhcp=dict(type='bool', required=False)
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    # Stub class to allow ansible-test to run without Redfish
    class iLOIPv4NTPServersModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO IPv4 NTP servers modules.
        """

        def __init__(self, *args, **kwargs) -> None:

            super().__init__(
                *args,
                argument_spec=ARGSPEC.copy(),
                required_if=[
                    ('use_dhcp', False, ['ntp_servers'])
                ],
                supports_check_mode=True,
                **kwargs
            )

        def get_ntp_server_config(self) -> dict:
            """
            Get the manager Ethernet NTP servers from the Redfish client.

            Returns:
                dict: The current IPv4 NTP server configuration, including NTP servers and whether DHCP is used.
            """

            pass

        def set_ntp_use_dhcp(self, use_dhcp: bool) -> None:
            """
            Set whether to use DHCP for NTP server configuration in the Redfish client.

            Args:
                use_dhcp (bool): Whether to use DHCP for NTP server configuration.
            """

            discard = use_dhcp
            pass

        def set_ntp_servers(self, ntp_servers: List[str]) -> None:
            """
            Set the manager Ethernet NTP servers in the Redfish client.

            Args:
                ntp_servers (List[str]): The list of NTP servers to set.
            """

            discard = ntp_servers
            pass

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOIPv4NTPServersModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO IPv4 NTP servers modules.
        """

        def __init__(self, *args, **kwargs) -> None:

            super().__init__(
                *args,
                argument_spec=ARGSPEC.copy(),
                required_if=[
                    ('use_dhcp', False, ['ntp_servers'])
                ],
                supports_check_mode=True,
                **kwargs
            )

        def get_ntp_server_config(self) -> dict:
            """
            Get the manager Ethernet NTP servers from the Redfish client.

            Returns:
                dict: The current IPv4 NTP server configuration, including NTP servers and whether DHCP is used.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_ethernet_uri: str = self.get_manager_ethernet_uri()

            try:
                response: RestResponse = self.client.get(manager_ethernet_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error retrieving manager Ethernet NTP servers', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message='Failed to retrieve manager Ethernet NTP servers'))

            if 'Oem' not in response.dict:
                self.handle_error(iLOModuleError(message='No Oem found in manager Ethernet'))

            oem: dict = response.dict['Oem']

            if 'Hpe' not in oem:
                self.handle_error(iLOModuleError(message='No Hpe found in manager Ethernet Oem'))

            hpe: dict = oem['Hpe']

            if 'DHCPv4' not in hpe:
                self.handle_error(iLOModuleError(message='No DHCPv4 found in manager Ethernet Oem Hpe'))

            dhcpv4: dict = hpe['DHCPv4']

            if 'UseNTPServers' not in dhcpv4:
                self.handle_error(iLOModuleError(message='No UseNTPServers found in manager Ethernet Oem Hpe DHCPv4'))

            use_dhcpv4: bool = dhcpv4['UseNTPServers']

            if 'DHCPv6' not in hpe:
                self.handle_error(iLOModuleError(message='No DHCPv6 found in manager Ethernet Oem Hpe'))

            dhcpv6: dict = hpe['DHCPv6']

            if 'UseNTPServers' not in dhcpv6:
                self.handle_error(iLOModuleError(message='No UseNTPServers found in manager Ethernet Oem Hpe DHCPv6'))

            use_dhcpv6: bool = dhcpv6['UseNTPServers']

            date_time_uri: str = self.get_manager_date_time_service_uri()

            try:
                response: RestResponse = self.client.get(date_time_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error retrieving manager DateTime', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message='Failed to retrieve manager DateTime'))

            if 'StaticNTPServers' not in response.dict:
                self.handle_error(iLOModuleError(message='No StaticNTPServers found in manager DateTime'))

            ntp_servers: List[str] = response.dict['StaticNTPServers']

            return dict(
                ntp_servers=ntp_servers,
                use_dhcpv4=use_dhcpv4,
                use_dhcpv6=use_dhcpv6
            )

        def set_ntp_use_dhcp(self, use_dhcp: bool) -> None:
            """
            Set whether to use DHCP for NTP server configuration in the Redfish client.

            Args:
                use_dhcp (bool): Whether to use DHCP for NTP server configuration.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_ethernet_uri: str = self.get_manager_ethernet_uri()

            payload: dict = dict(
                Oem=dict(
                    Hpe=dict(
                        DHCPv4=dict(
                            UseNTPServers=use_dhcp
                        ),
                        DHCPv6=dict(
                            UseNTPServers=use_dhcp
                        )
                    )
                )
            )

            try:
                response: RestResponse = self.client.patch(manager_ethernet_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error setting manager Ethernet IPv4 UseNTPServers', exception=to_native(e)))

            if response.status not in [200, 204]:
                self.handle_error(iLOModuleError(message='Failed to set manager Ethernet IPv4 UseNTPServers'))

        def set_ntp_servers(self, ntp_servers: List[str]) -> None:
            """
            Set the manager Ethernet NTP servers in the Redfish client.

            Args:
                ntp_servers (List[str]): The list of NTP servers to set.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            date_time_uri: str = self.get_manager_date_time_service_uri()

            payload: dict = dict(StaticNTPServers=ntp_servers)

            try:
                response: RestResponse = self.client.patch(date_time_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error setting manager Ethernet IPv4 NTP servers', exception=to_native(e)))

            if response.status not in [200, 204]:
                self.handle_error(iLOModuleError(message='Failed to set manager Ethernet IPv4 NTP servers'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOIPv4NTPServersModule = iLOIPv4NTPServersModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    ntp_servers: Optional[List[str]] = module.params.get('ntp_servers', None)
    use_dhcp: Optional[bool] = module.params.get('use_dhcp', None)

    if use_dhcp is None:
        use_dhcp = ntp_servers is None

    if use_dhcp and ntp_servers is not None:
        module.fail_json(msg='Cannot specify ntp_servers when use_dhcp is true.')

    if ntp_servers is not None:

        for ntp_server in ntp_servers:
            if not validate_ipv4(ntp_server) and not validate_ipv6(ntp_server):
                module.fail_json(msg=f'Invalid IP address: {ntp_server}')

        if (len(ntp_servers) > 2):
            module.fail_json(msg='The list of NTP servers must contain no more than two servers.')

        if (len(ntp_servers) == 0):
            ntp_servers.append('')

        if (len(ntp_servers) == 1):
            ntp_servers.append('')

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    current_ntp_config: dict = module.get_ntp_server_config()
    current_ntp_servers: List[str] = current_ntp_config["ntp_servers"]
    current_use_dhcpv4: bool = current_ntp_config["use_dhcpv4"]
    current_use_dhcpv6: bool = current_ntp_config["use_dhcpv6"]

    if not current_use_dhcpv4 or not current_use_dhcpv6:
        result["diff"]["before"]["ntp_servers"] = current_ntp_servers

    result["diff"]["before"]["use_dhcpv4"] = current_use_dhcpv4
    result["diff"]["before"]["use_dhcpv6"] = current_use_dhcpv6

    if not use_dhcp:
        result["diff"]["after"]["ntp_servers"] = ntp_servers
        result["ntp_servers"] = ntp_servers

    result["diff"]["after"]["use_dhcpv4"] = use_dhcp
    result["diff"]["after"]["use_dhcpv6"] = use_dhcp
    result["use_dhcp"] = use_dhcp

    if use_dhcp != current_use_dhcpv4 or use_dhcp != current_use_dhcpv6:

        result["changed"] = True

        if not module.check_mode:
            module.set_ntp_use_dhcp(use_dhcp)

    if (not use_dhcp and
        (current_ntp_servers[0] != ntp_servers[0] or
         current_ntp_servers[1] != ntp_servers[1])):

        result["changed"] = True

        if not module.check_mode:
            module.set_ntp_servers(ntp_servers)

    module.logout()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
