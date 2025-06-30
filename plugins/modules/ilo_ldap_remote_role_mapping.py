#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_ldap_remote_role_mapping
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures iLO LDAP remote role mapping
description:
  - >-
    This module configures the LDAP remote role mapping for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  ldap_group:
    type: str
    required: true
    description:
      - The LDAP group to map to the local role.
  local_role:
    type: str
    required: false
    description:
      - The local role whose permissions are granted to the LDAP group.
      - This is only used when creating the mapping.
      - If O(state=present), this is required.
      - If O(state=absent), this should not be provided.
  state:
    type: str
    required: false
    default: present
    choices:
      - present
      - absent
    description:
      - The state of the LDAP remote role mapping.
"""

EXAMPLES = r"""
- name: Add LDAP remote role mapping
  trippsc2.hpe.ilo_ldap_remote_role_mapping:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    local_role: 'Administrator'
    ldap_group: 'ilo-admins'
    state: present

- name: Remove LDAP remote role mapping
  trippsc2.hpe.ilo_ldap_remote_role_mapping:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    local_role: 'Administrator'
    ldap_group: 'ilo-admins'
    state: absent
"""

RETURN = r"""
ldap_remote_role_mapping:
  type: list
  returned: O(state=present)
  elements: dict
  description:
    - The LDAP remote role mappings configured on the iLO device.
  contains:
    ldap_group:
      type: str
      description:
        - The LDAP group mapped to the local role.
    local_role:
      type: str
      returned: Not changed or Not check mode
      description:
        - The local role mapped to the LDAP group.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError

from typing import List, Optional

MODULE_INIT_ARGS: dict = dict(
    argument_spec=dict(
        ldap_group=dict(type='str', required=True),
        local_role=dict(type='str', required=False),
        state=dict(type='str', required=False, default='present', choices=['present', 'absent'])
    ),
    required_if=[
        ('state', 'present', ['local_role'])
    ],
    supports_check_mode=True
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = to_native(traceback.format_exc())

    # Stub class to allow ansible-test to run without Redfish
    class iLOLdapRemoteRoleModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO LDAP remote role mapping modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

        def format_ldap_remote_role_mapping(self, mapping: dict) -> dict:
            """
            Formats the LDAP remote role mapping for output.
            """

            discard = mapping

        def format_ldap_remote_role_mapping_payload(self, mapping: dict) -> dict:
            """
            Formats the LDAP remote role mapping for payload.
            """

            discard = mapping

        def get_ldap_remote_role_mappings(self) -> List[dict]:
            """
            Retrieves the current LDAP remote role mappings from the iLO device.
            """

            pass

        def configure_ldap_remote_role_mappings(self, mappings: List[dict]) -> None:
            """
            Configures the LDAP remote role mappings on the iLO device.
            """

            discard = mappings

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOLdapRemoteRoleModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO LDAP remote role mapping modules.
        """

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **MODULE_INIT_ARGS, **kwargs)

        def format_ldap_remote_role_mapping(self, mapping: dict) -> dict:
            """
            Formats the LDAP remote role mapping for output.
            """

            return dict(
                local_role=mapping['LocalRole'],
                ldap_group=mapping['RemoteGroup']
            )

        def format_ldap_remote_role_mapping_payload(self, mapping: dict) -> dict:
            """
            Formats the LDAP remote role mapping for payload.
            """

            return dict(
                LocalRole=mapping['local_role'],
                RemoteGroup=mapping['ldap_group']
            )

        def get_ldap_remote_role_mappings(self) -> List[dict]:
            """
            Retrieves the current LDAP remote role mappings from the iLO device.
            """

            account_service_uri: str = self.get_account_service_uri()

            try:
                response: RestResponse = self.client.get(account_service_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {account_service_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {account_service_uri}'))

            if 'LDAP' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'LDAP\' not found in {account_service_uri}'))

            ldap: dict = response.dict['LDAP']

            if 'RemoteRoleMapping' not in ldap:
                return []

            remote_role_mappings: List[dict] = ldap['RemoteRoleMapping']

            ldap_remote_role_mappings: List[dict] = []

            for mapping in remote_role_mappings:
                ldap_remote_role_mappings.append(self.format_ldap_remote_role_mapping(mapping))

            return ldap_remote_role_mappings

        def configure_ldap_remote_role_mappings(self, mappings: List[dict]) -> None:
            """
            Configures the LDAP remote role mappings on the iLO device.
            """

            account_service_uri: str = self.get_account_service_uri()

            payload_mappings: List[dict] = []

            for mapping in mappings:
                payload_mappings.append(self.format_ldap_remote_role_mapping_payload(mapping))

            payload: dict = dict(
                LDAP=dict(
                    RemoteRoleMapping=payload_mappings
                )
            )

            try:
                response: RestResponse = self.client.patch(account_service_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error configuring LDAP remote role mappings', exception=to_native(e)))

            if response.status not in [200, 201]:
                self.handle_error(iLOModuleError(message='Failed to configure LDAP remote role mappings'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOLdapRemoteRoleModule = iLOLdapRemoteRoleModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    ldap_group: str = module.params['ldap_group']
    local_role: Optional[str] = module.params.get('local_role', None)
    state: str = module.params['state']

    if state == 'absent' and local_role is not None:
        module.fail_json(msg='When state is absent, local_role must not be provided.')

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    mappings: List[dict] = module.get_ldap_remote_role_mappings()

    result['diff']['before']['ldap_remote_role_mappings'] = mappings.copy()

    matching_mapping: Optional[dict] = None

    for mapping in mappings:
        if mapping['ldap_group'] == ldap_group:
            matching_mapping = mapping
            break

    if state == 'absent':

        if matching_mapping is not None:

            mappings.remove(matching_mapping)

            result['changed'] = True
            result['diff']['after']['ldap_remote_role_mappings'] = mappings.copy()

            if not module.check_mode:
                module.configure_ldap_remote_role_mappings(mappings)

        else:
            result['diff']['after']['ldap_remote_role_mappings'] = mappings.copy()

    elif state == 'present':

        if matching_mapping is None:

            new_mapping: dict = dict(
                local_role=local_role,
                ldap_group=ldap_group
            )

            mappings.append(new_mapping)

            result['changed'] = True
            result['diff']['after']['ldap_remote_role_mappings'] = mappings.copy()
            result['ldap_remote_role_mapping'] = dict(ldap_group=ldap_group)

            if not module.check_mode:

                module.configure_ldap_remote_role_mappings(mappings)

                mappings = module.get_ldap_remote_role_mappings()

                for mapping in mappings:
                    if mapping['ldap_group'] == ldap_group:
                        matching_mapping = mapping
                        break

                result['diff']['after']['ldap_remote_role_mappings'] = mappings.copy()
                result['ldap_remote_role_mapping']['local_role'] = matching_mapping['local_role']

        else:
            result['diff']['after']['ldap_remote_role_mappings'] = mappings.copy()
            result['ldap_remote_role_mapping'] = dict(
                ldap_group=matching_mapping['ldap_group'],
                local_role=matching_mapping['local_role']
            )

    else:
        module.handle_error(iLOModuleError(message=f'Invalid state: {state}. Must be one of: present, absent'))

    module.logout()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
