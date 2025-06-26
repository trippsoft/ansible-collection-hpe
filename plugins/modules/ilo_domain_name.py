#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_domain_name
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures iLO domain name.
description:
  - >-
    This module configures the domain name for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  domain_name:
    type: str
    required: false
    description:
      - The domain name to configure for the iLO device.
  use_dhcp:
    type: bool
    required: false
    description:
      - Whether to use DHCP to configure the domain name.
      - If set to true, the domain name will be configured via DHCP.
      - If set to false, the domain name will be set to the value specified in C(domain_name).
      - If O(domain_name) is specified, this will default to V(false).
      - If O(domain_name) is not specified, this will default to V(true).
      - If O(domain_name) is specified and O(use_dhcp) is set to V(true), the module will fail.
"""

EXAMPLES = r"""
- name: Configure iLO domain name
  trippsc2.hpe.ilo_domain_name:
    base_url: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    domain_name: "ilo-domain-name.loc"

- name: Configure iLO domain name with DHCP
  trippsc2.hpe.ilo_domain_name:
    base_url: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    use_dhcp: true
"""

RETURN = r"""
domain_name:
  type: str
  returned: O(domain_name) is specified
  description:
    - The configured domain name for the iLO device.
use_dhcp:
  type: bool
  returned: always
  description:
    - Whether DHCP is used to configure the domain name.
    - If true, the domain name is obtained via DHCP.
    - If false, the domain name is configured manually.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError
from ..module_utils.ilo_utils import validate_hostname

from typing import Optional

MODULE_INIT_ARGS: dict = dict(
    argument_spec=dict(
        domain_name=dict(type='str', required=False),
        use_dhcp=dict(type='bool', required=False)
    ),
    required_if=[
        ('use_dhcp', False, ['domain_name'])
    ],
    supports_check_mode=True
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    # Stub class to allow ansible-test to run without Redfish
    class iLODomainNameModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO domain name modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

        def get_domain_name_config(self) -> dict:
            """
            Get the domain name from the Redfish client.

            Returns:
                str: The domain name configuration.
            """

            pass

        def set_domain_name_use_dhcp(self, use_dhcp: bool) -> None:
            """
            Set the manager Ethernet domain name use DHCP in the Redfish client.

            Args:
                use_dhcp (bool): Whether to use DHCP for the domain name.
            """

            discard = use_dhcp

        def set_domain_name(self, domain_name: str) -> None:
            """
            Set the manager Ethernet domain name in the Redfish client.

            Args:
                domain_name (str): The domain name to set.
            """

            discard = domain_name

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLODomainNameModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO domain name modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

        def get_domain_name_config(self) -> dict:
            """
            Get the domain name from the Redfish client.

            Returns:
                str: The domain name configuration.
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

            if 'DHCPv4' not in hpe:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.DHCPv4\' is not found in {manager_ethernet_uri}'))

            dhcpv4: dict = hpe['DHCPv4']

            if 'UseDomainName' not in dhcpv4:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.DHCPv4.UseDomainName\' is not found in {manager_ethernet_uri}'))

            use_dhcpv4: bool = dhcpv4['UseDomainName']

            if 'DHCPv6' not in hpe:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.DHCPv6\' is not found in {manager_ethernet_uri}'))

            dhcpv6: dict = hpe['DHCPv6']

            if 'UseDomainName' not in dhcpv6:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.DHCPv6.UseDomainName\' is not found in {manager_ethernet_uri}'))

            use_dhcpv6: bool = dhcpv6['UseDomainName']

            if 'DomainName' not in hpe:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.DomainName\' is not found in {manager_ethernet_uri}'))

            domain_name: str = hpe['DomainName']

            return dict(
                domain_name=domain_name,
                use_dhcpv4=use_dhcpv4,
                use_dhcpv6=use_dhcpv6
            )

        def set_domain_name_use_dhcp(self, use_dhcp: bool) -> None:
            """
            Set the manager Ethernet domain name use DHCP in the Redfish client.

            Args:
                use_dhcp (bool): Whether to use DHCP for the domain name.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_ethernet_uri: str = self.get_manager_ethernet_uri()

            payload: dict = dict(
                Oem=dict(
                    Hpe=dict(
                        DHCPv4=dict(
                            UseDomainName=use_dhcp
                        ),
                        DHCPv6=dict(
                            UseDomainName=use_dhcp
                        )
                    )
                )
            )

            try:
                response: RestResponse = self.client.patch(manager_ethernet_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error occurred when configuring DHCP domain name behavior', exception=to_native(e)))

            if response.status not in [200, 204]:
                self.handle_error(iLOModuleError(message='Failed to configure DHCP domain name behavior'))

        def set_domain_name(self, domain_name: str) -> None:
            """
            Set the manager Ethernet domain name in the Redfish client.

            Args:
                domain_name (str): The domain name to set.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_ethernet_uri: str = self.get_manager_ethernet_uri()

            payload: dict = dict(
                Oem=dict(
                    Hpe=dict(
                        DomainName=domain_name
                    )
                )
            )

            try:
                response: RestResponse = self.client.patch(manager_ethernet_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error occurred when configuring domain name', exception=to_native(e)))

            if response.status not in [200, 204]:
                self.handle_error(iLOModuleError(message='Failed to configure domain name'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLODomainNameModule = iLODomainNameModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    domain_name: Optional[str] = module.params.get('domain_name', None)
    use_dhcp: Optional[bool] = module.params.get('use_dhcp', None)

    if use_dhcp is None:
        use_dhcp = domain_name is None

    if domain_name is not None and use_dhcp:
        module.fail_json(
            msg='The domain_name parameter cannot be specified when use_dhcp is set to true'
        )

    if domain_name is not None:
        for label in domain_name.split('.'):
            if not validate_hostname(label):
                module.fail_json(
                    msg=f'The domain name "{domain_name}" is not valid. Each label must be a valid hostname'
                )

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    current_domain_name_config: dict = module.get_domain_name_config()

    current_domain_name: str = current_domain_name_config['domain_name']
    current_use_dhcpv4: bool = current_domain_name_config['use_dhcpv4']
    current_use_dhcpv6: bool = current_domain_name_config['use_dhcpv6']

    result["diff"]["before"]["use_dhcpv4"] = current_use_dhcpv4
    result["diff"]["before"]["use_dhcpv6"] = current_use_dhcpv6

    if not current_use_dhcpv4 or not current_use_dhcpv6:
        result["diff"]["before"]["domain_name"] = current_domain_name

    result["diff"]["after"]["use_dhcpv4"] = use_dhcp
    result["diff"]["after"]["use_dhcpv6"] = use_dhcp
    result["use_dhcp"] = use_dhcp

    if not use_dhcp:
        result["diff"]["after"]["domain_name"] = domain_name
        result["domain_name"] = domain_name

    if current_use_dhcpv4 != use_dhcp or current_use_dhcpv6 != use_dhcp:

        result["changed"] = True

        if not module.check_mode:
            module.set_domain_name_use_dhcp(use_dhcp)

    if not use_dhcp and current_domain_name != domain_name:

        result["changed"] = True

        if not module.check_mode:
            module.set_domain_name(domain_name)

    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
