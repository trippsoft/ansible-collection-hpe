#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_snmp_community
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures iLO SNMP community strings.  This only configures request community strings.
description:
  - >-
    This module configures the SNMP community strings for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  name:
    type: str
    required: true
    description:
      - The name of the SNMP community string to configure.
  state:
    type: str
    required: false
    default: 'present'
    choices:
      - present
      - absent
    description:
      - The state of the SNMP community string.
      - If V(present), the community string will be configured.
      - If V(absent), the community string will be removed.
"""

EXAMPLES = r"""
- name: Configure iLO SNMP community string
  trippsc2.hpe.ilo_snmp_community:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    name: 'public'
    state: 'present'

- name: Remove iLO SNMP community string
  trippsc2.hpe.ilo_snmp_community:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    name: 'public'
    state: 'absent'
"""

RETURN = r"""
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import COMMON_ARGSPEC, iLOModule
from ..module_utils.ilo_module_error import iLOModuleError

from typing import List, Optional

ARGSPEC: dict = dict(
    name=dict(type='str', required=True),
    state=dict(
        type='str',
        required=False,
        default='present',
        choices=['present', 'absent']
    )
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    class iLOSNMPCommunityModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO SNMP community modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, argument_spec=ARGSPEC.copy(), supports_check_mode=True, **kwargs)

        def get_snmp_communities(self) -> List[str]:
            """
            Get the SNMP community configuration from the Redfish client.

            Returns:
                List[str]: A list of SNMP community strings.
            """

            pass

        def set_snmp_communities(self, communities: List[str]) -> None:
            """
            Set the SNMP community configuration on the Redfish client.

            Args:
                communities (List[str]): A list of SNMP community strings to configure.
            """

            discard = communities
            pass

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOSNMPCommunityModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO SNMP community modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, argument_spec=ARGSPEC.copy(), supports_check_mode=True, **kwargs)

        def get_snmp_communities(self) -> List[str]:
            """
            Get the SNMP community configuration from the Redfish client.

            Returns:
                List[str]: A list of SNMP community strings.
            """

            snmp_service_uri: str = self.get_manager_snmp_service_uri()

            try:
                response: RestResponse = self.client.get(snmp_service_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {snmp_service_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {snmp_service_uri}'))

            if 'ReadCommunities' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'ReadCommunities\' not found in {snmp_service_uri}'))

            communities: List[str] = response.dict['ReadCommunities']

            while '' in communities:
                communities.remove('')

            return communities

        def set_snmp_communities(self, communities: List[str]) -> None:
            """
            Set the SNMP community configuration on the Redfish client.

            Args:
                communities (List[str]): A list of SNMP community strings to configure.
            """

            snmp_service_uri: str = self.get_manager_snmp_service_uri()

            payload: dict = dict(ReadCommunities=communities)

            try:
                response: RestResponse = self.client.patch(snmp_service_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error configuring SNMP communities', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message='Failed to configure SNMP communities'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOSNMPCommunityModule = iLOSNMPCommunityModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    name: str = module.params['name']
    state: str = module.params['state']

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    current_communities: List[str] = module.get_snmp_communities()

    result['diff']['before']['communities'] = current_communities

    if state == 'present':
        if name not in current_communities:

            result['changed'] = True

            desired_communities: List[str] = current_communities.copy().append(name)
            result['diff']['after']['communities'] = desired_communities

            if not module.check_mode:
                module.set_snmp_communities(desired_communities)

        else:
            result['diff']['after']['communities'] = current_communities
    elif state == 'absent':
        if name in current_communities:

            result['changed'] = True

            desired_communities: List[str] = current_communities.copy()
            desired_communities.remove(name)
            result['diff']['after']['communities'] = desired_communities

            if not module.check_mode:
                module.set_snmp_communities(desired_communities)

        else:
            result['diff']['after']['communities'] = current_communities
    else:
        module.fail_json(msg=f'Invalid state: {state}')

    module.logout()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
