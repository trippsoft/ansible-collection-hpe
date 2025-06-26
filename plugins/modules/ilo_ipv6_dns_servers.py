#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_ipv6_dns_servers
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures iLO IPv6 DNS servers.
description:
  - >-
    This module configures the IPv6 DNS servers for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  dns_servers:
    type: list
    required: false
    elements: str
    description:
      - The list of IPv6 DNS servers to configure.
      - Each server should be specified as a string in colon-separated hexadecimal notation (e.g., "2001:db8::1").
      - The list must contain no more than three servers.
  use_dhcp:
    type: bool
    required: false
    description:
      - Indicates whether to use DHCP for IPv6 DNS server configuration.
      - If true, the iLO will use DHCP to obtain IPv6 DNS servers.
      - If false, the DNS servers must be specified in the C(dns_servers) parameter.
      - If O(dns_servers) is provided, this option will default to V(false).
      - If O(dns_servers) is not provided, this option will default to V(true).
      - If O(dns_servers) is provided and this is V(true), the module will fail.
"""

EXAMPLES = r"""
- name: Configure iLO IPv6 DNS servers
  trippsc2.hpe.ilo_ipv6_dns_servers:
    base_url: '2001:db8::200'
    username: 'Administrator'
    password: 'password'
    dns_servers:
      - "2001:db8::1"
      - "2001:db8::2"
      - "2001:db8::3"

- name: Configure iLO IPv6 DNS servers with DHCP
  trippsc2.hpe.ilo_ipv6_dns_servers:
    base_url: '2001:db8::200'
    username: 'Administrator'
    password: 'password'
    use_dhcp: true
"""

RETURN = r"""
dns_servers:
  type: list
  returned: O(dns_servers) is specified
  elements: str
  description:
    - The list of configured IPv6 DNS servers.
use_dhcp:
  type: bool
  returned: always
  description:
    - Indicates whether DHCP is used for IPv6 DNS server configuration.
    - If true, the DNS servers are obtained via DHCP.
    - If false, the DNS servers are configured manually.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError
from ..module_utils.ilo_utils import validate_ipv6

from typing import List, Optional

ARGSPEC: dict = dict(
    dns_servers=dict(type='list', required=False, elements='str'),
    use_dhcp=dict(type='bool', required=False)
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    # Stub class to allow ansible-test to run without Redfish
    class iLOIPv6DNSServersModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO IPv6 DNS servers modules.
        """

        def __init__(self, *args, **kwargs) -> None:

            super().__init__(
                *args,
                argument_spec=ARGSPEC.copy(),
                required_if=[
                    ('use_dhcp', False, ['dns_servers'])
                ],
                supports_check_mode=True,
                **kwargs
            )

        def get_ipv6_dns_server_config(self) -> dict:
            """
            Get the manager Ethernet DNS servers from the Redfish client.

            Returns:
                dict: The current IPv6 DNS server configuration, including DNS servers and whether DHCP is used.
            """

            pass

        def set_ipv6_use_dhcp(self, use_dhcp: bool) -> None:
            """
            Set whether to use DHCP for IPv6 DNS server configuration in the Redfish client.

            Args:
                use_dhcp (bool): Whether to use DHCP for IPv6 DNS server configuration.
            """

            discard = use_dhcp
            pass

        def set_ipv6_dns_servers(self, dns_servers: List[str]) -> None:
            """
            Set the manager Ethernet DNS servers in the Redfish client.

            Args:
                dns_servers (List[str]): The list of DNS servers to set.
            """

            discard = dns_servers
            pass

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOIPv6DNSServersModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO IPv6 DNS servers modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, argument_spec=ARGSPEC.copy(), supports_check_mode=True, **kwargs)

        def get_ipv6_dns_server_config(self) -> dict:
            """
            Get the manager Ethernet DNS servers from the Redfish client.

            Returns:
                dict: The current IPv6 DNS server configuration, including DNS servers and whether DHCP is used.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_ethernet_uri: str = self.get_manager_ethernet_uri()

            try:
                response: RestResponse = self.client.get(manager_ethernet_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {manager_ethernet_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {manager_ethernet_uri}'))

            if 'Oem' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Oem\' is not found in {manager_ethernet_uri}'))

            oem: dict = response.dict['Oem']

            if 'Hpe' not in oem:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe\' is not found in {manager_ethernet_uri}'))

            hpe: dict = oem['Hpe']

            if 'DHCPv6' not in hpe:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.DHCPv6\' is not found in {manager_ethernet_uri}'))

            dhcpv6: dict = hpe['DHCPv6']

            if 'UseDNSServers' not in dhcpv6:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.DHCPv6.UseDNSServers\' is not found in {manager_ethernet_uri}'))

            use_dhcp: bool = dhcpv6['UseDNSServers']

            if 'IPv6' not in hpe:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.IPv6\' is not found in {manager_ethernet_uri}'))

            ipv6: dict = hpe['IPv6']

            if 'DNSServers' not in ipv6:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.IPv6.DNSServers\' is not found in {manager_ethernet_uri}'))

            dns_servers: List[str] = ipv6['DNSServers']

            return dict(
                dns_servers=dns_servers,
                use_dhcp=use_dhcp
            )

        def set_ipv6_use_dhcp(self, use_dhcp: bool) -> None:
            """
            Set whether to use DHCP for IPv6 DNS server configuration in the Redfish client.

            Args:
                use_dhcp (bool): Whether to use DHCP for IPv6 DNS server configuration.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_ethernet_uri: str = self.get_manager_ethernet_uri()

            payload: dict = dict(
                Oem=dict(
                    Hpe=dict(
                        DHCPv6=dict(
                            UseDNSServers=use_dhcp
                        )
                    )
                )
            )

            try:
                response: RestResponse = self.client.patch(manager_ethernet_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error occurred when configuring DHCP DNS behavior', exception=to_native(e)))

            if response.status not in [200, 204]:
                self.handle_error(iLOModuleError(message='Failed to configure DHCP DNS behavior'))

        def set_ipv6_dns_servers(self, dns_servers: List[str]) -> None:
            """
            Set the manager Ethernet DNS servers in the Redfish client.

            Args:
                dns_servers (List[str]): The list of DNS servers to set.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_ethernet_uri: str = self.get_manager_ethernet_uri()

            payload: dict = dict(
                Oem=dict(
                    Hpe=dict(
                        IPv6=dict(
                            DNSServers=dns_servers
                        )
                    )
                )
            )

            try:
                response: RestResponse = self.client.patch(manager_ethernet_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error occurred when configuring IPv6 DNS servers', exception=to_native(e)))

            if response.status not in [200, 204]:
                self.handle_error(iLOModuleError(message='Failed to configure IPv6 DNS servers'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOIPv6DNSServersModule = iLOIPv6DNSServersModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    dns_servers: Optional[List[str]] = module.params.get('dns_servers', None)
    use_dhcp: Optional[bool] = module.params.get('use_dhcp', None)

    if use_dhcp is None:
        use_dhcp: bool = dns_servers is None

    if use_dhcp and dns_servers is not None:
        module.fail_json(msg='Cannot specify dns_servers when use_dhcp is true')

    if dns_servers is not None:
        for dns_server in dns_servers:
            if not validate_ipv6(dns_server):
                module.fail_json(msg=f'Invalid IPv6 address: {dns_server}')

        if (len(dns_servers) > 3):
            module.fail_json(msg='The list of DNS servers must contain no more than three servers')

        if (len(dns_servers) == 0):
            dns_servers.append('::')

        if (len(dns_servers) == 1):
            dns_servers.append('::')

        if (len(dns_servers) == 2):
            dns_servers.append('::')

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    current_dns_config: List[str] = module.get_ipv6_dns_server_config()

    current_dns_servers: List[str] = current_dns_config['dns_servers']
    current_use_dhcp: bool = current_dns_config['use_dhcp']

    result["diff"]["before"]["use_dhcp"] = current_use_dhcp

    if not current_use_dhcp:
        result["diff"]["before"]["dns_servers"] = current_dns_servers

    result["diff"]["after"]["use_dhcp"] = use_dhcp
    result["use_dhcp"] = use_dhcp

    if not use_dhcp:
        result["diff"]["after"]["dns_servers"] = dns_servers
        result["dns_servers"] = dns_servers

    if current_use_dhcp != use_dhcp:

        result["changed"] = True

        if not module.check_mode:
            module.set_ipv6_use_dhcp(use_dhcp)

    if (not use_dhcp and
        (current_dns_servers[0] != dns_servers[0] or
         current_dns_servers[1] != dns_servers[1] or
         current_dns_servers[2] != dns_servers[2])):

        result["changed"] = True

        if not module.check_mode:
            module.set_ipv6_dns_servers(dns_servers)

    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
