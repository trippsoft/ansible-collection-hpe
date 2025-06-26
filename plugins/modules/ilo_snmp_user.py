#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_snmp_user
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures iLO SNMP user settings.
description:
  - >-
    This module configures the SNMP user settings for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  security_name:
    type: str
    required: true
    aliases:
      - 'name'
    description:
      - The security name for the SNMP user.
      - The value must be unique across all SNMP users and be between 1 and 32 characters in length.
  auth_protocol:
    type: str
    required: false
    choices:
      - 'sha256'
      - 'sha'
      - 'md5'
    description:
      - The authentication protocol for the SNMP user.
      - If not provided, the default of V(sha) will be used if the user is created.
      - If O(state=absent), this option should not be provided.
  auth_passphrase:
    type: str
    required: false
    description:
      - The authentication passphrase for the SNMP user.
      - The value must be between 8 and 49 characters in length.
      - If O(state=present), this option is required.
      - If O(state=absent), this option should not be provided.
      - If O(update_passphrase='on_create'), this passphrase will only be set when the user is created.
  priv_protocol:
    type: str
    required: false
    choices:
      - 'aes'
    description:
      - The privacy protocol for the SNMP user.
      - If not provided, the default of V(aes) will be used if the user is created.
      - If O(state=absent), this option should not be provided.
  priv_passphrase:
    type: str
    required: false
    description:
      - The privacy passphrase for the SNMP user.
      - The value must be between 8 and 49 characters in length.
      - If O(state=present), this option is required.
      - If O(state=absent), this option should not be provided.
      - If O(update_passphrase='on_create'), this passphrase will only be set when the user is created.
  update_passphrase:
    type: str
    required: false
    default: 'on_create'
    choices:
      - 'on_create'
      - 'always'
    description:
      - When to update the passphrase for the SNMP user.
      - If O(state=absent), this option is ignored.
  user_engine_id:
    type: str
    required: false
    description:
      - The user engine ID for the SNMP user.
      - If O(state=absent), this option should not be provided.
  state:
    type: str
    required: false
    default: 'present'
    choices:
      - 'present'
      - 'absent'
    description:
      - The state of the SNMP user.
      - If V(present), the SNMP user will be configured.
      - If V(absent), the SNMP user will be removed.
"""

EXAMPLES = r"""
- name: Configure iLO SNMP user
  trippsc2.hpe.ilo_snmp_user:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    security_name: 'snmp_user'
    auth_protocol: 'sha'
    auth_passphrase: 'auth_pass'
    priv_protocol: 'aes'
    priv_passphrase: 'priv_pass'
    state: 'present'

- name: Remove iLO SNMP user
  trippsc2.hpe.ilo_snmp_user:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    security_name: 'snmp_user'
    state: 'absent'
"""

RETURN = r"""
security_name:
  type: str
  returned: O(state=present)
  description:
    - The security name of the SNMP user.
auth_protocol:
  type: str
  returned: O(state=present)
  description:
    - The authentication protocol used by the SNMP user.
priv_protocol:
  type: str
  returned: O(state=present)
  description:
    - The privacy protocol used by the SNMP user.
engine_id:
  type: str
  returned: O(state=present)
  description:
    - The user engine ID for the SNMP user.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import COMMON_ARGSPEC, iLOModule
from ..module_utils.ilo_module_error import iLOModuleError

from typing import List, Optional

MODULE_INIT_ARGS: dict = dict(
    argument_spec=dict(
        security_name=dict(type='str', required=True, aliases=['name']),
        auth_protocol=dict(type='str', required=False, choices=['sha256', 'sha', 'md5']),
        auth_passphrase=dict(type='str', required=False, no_log=True),
        priv_protocol=dict(type='str', required=False, choices=['aes']),
        priv_passphrase=dict(type='str', required=False, no_log=True),
        update_passphrase=dict(type='str', required=False, default='on_create', choices=['on_create', 'always'], no_log=False),
        user_engine_id=dict(type='str', required=False),
        state=dict(type='str', required=False, default='present', choices=['present', 'absent'])
    ),
    required_if=[
        ('state', 'present', ['auth_passphrase', 'priv_passphrase'])
    ],
    supports_check_mode=True
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    class iLOSnmpUserModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO SNMP user modules.
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

        def get_snmp_user(self, security_name: str) -> Optional[dict]:
            """
            Get the SNMP user configuration from the Redfish client.

            Args:
                security_name (str): The security name of the SNMP user.

            Returns:
                Optional[dict]: The SNMP user configuration, or None if not found.
            """

            discard = security_name
            pass

        def format_snmp_user(self, user: dict) -> dict:
            """
            Format the SNMP user dictionary to match the expected structure.

            Args:
                user (dict): The SNMP user configuration.

            Returns:
                dict: The formatted SNMP user configuration.
            """

            discard = user
            pass

        def get_next_snmp_user_index(self) -> int:
            """
            Get the next available index for a new SNMP user.

            Returns:
                int: The next available index for a new SNMP user.
            """

            pass

        def create_snmp_user(self, desired: dict) -> None:
            """
            Create a new SNMP user in the Redfish client.

            Args:
                desired (dict): The desired SNMP user configuration.
            """

            discard = desired
            pass

        def get_changes_needed(self, current: dict, desired: dict) -> dict:
            """
            Get the changes needed between the current and desired SNMP user configuration.

            Args:
                current (dict): The current SNMP user configuration.
                desired (dict): The desired SNMP user configuration.

            Returns:
                dict: The changes needed to update the current configuration to match the desired configuration.
            """

            discard = current
            discard = desired
            pass

        def update_snmp_user(self, changes: dict) -> None:
            """
            Update an existing SNMP user in the Redfish client.

            Args:
                changes (dict): The changes to apply to the SNMP user configuration.
            """

            discard = changes
            pass

        def delete_snmp_user(self, user: dict) -> None:
            """
            Delete an existing SNMP user in the Redfish client.

            Args:
                user (dict): The SNMP user configuration to delete.
            """

            discard = user
            pass

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOSnmpUserModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO SNMP user modules.
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

            for key in MODULE_INIT_ARGS['argument_spec'].keys():
                if desired_config.get(key, None) is None:
                    del desired_config[key]

            for key in COMMON_ARGSPEC.keys():
                if key in desired_config:
                    del desired_config[key]

            if 'state' in desired_config:
                del desired_config['state']

            if 'update_passphrase' in desired_config:
                if desired_config['update_passphrase'] == 'on_create':
                    del desired_config['update_passphrase']

            return desired_config

        def get_snmp_user(self, security_name: str) -> Optional[dict]:
            """
            Get the SNMP user configuration from the Redfish client.

            Args:
                security_name (str): The security name of the SNMP user.

            Returns:
                Optional[dict]: The SNMP user configuration, or None if not found.
            """

            snmp_service_uri: str = self.get_manager_snmp_service_uri()

            try:
                response: RestResponse = self.client.get(snmp_service_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {snmp_service_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {snmp_service_uri}'))

            if 'Users' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Users\' not found in {snmp_service_uri}'))

            users: list[dict] = response.dict['Users']

            for user in users:
                if user.get('SecurityName') == security_name:

                    formatted_user: dict = self.format_snmp_user(user)
                    formatted_user['index'] = users.index(user) + 1

                    return formatted_user

        def format_snmp_user(self, user: dict) -> dict:
            """
            Format the SNMP user dictionary to match the expected structure.

            Args:
                user (dict): The SNMP user configuration.

            Returns:
                dict: The formatted SNMP user configuration.
            """

            return dict(
                security_name=user['SecurityName'],
                auth_protocol=user['AuthProtocol'],
                priv_protocol=user['PrivacyProtocol'],
                user_engine_id=user['UserEngineID']
            )

        def get_next_snmp_user_index(self) -> int:
            """
            Get the next available index for a new SNMP user.

            Returns:
                int: The next available index for a new SNMP user.
            """

            empty_user: dict = self.get_snmp_user('')

            if empty_user is None:
                self.handle_error(iLOModuleError(message='SNMP users cannot be created because no empty user is available'))

            return empty_user['index']

        def create_snmp_user(self, desired: dict) -> None:
            """
            Create a new SNMP user in the Redfish client.

            Args:
                desired (dict): The desired SNMP user configuration.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            snmp_users_uri: str = self.get_manager_snmp_users_uri()

            payload: dict = dict(
                SecurityName=desired['security_name'],
                AuthProtocol=desired.get('auth_protocol', 'sha').upper(),
                AuthPassphrase=desired['auth_passphrase'],
                PrivacyProtocol=desired.get('priv_protocol', 'aes').upper(),
                PrivacyPassphrase=desired['priv_passphrase']
            )

            if 'user_engine_id' in desired:
                payload['UserEngineID'] = desired['user_engine_id']

            try:
                response: RestResponse = self.client.post(snmp_users_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error occurred when creating SNMP user', exception=to_native(e)))

            if response.status not in [200, 201]:
                self.handle_error(iLOModuleError(message='Failed to create SNMP user'))

        def get_changes_needed(self, current: dict, desired: dict) -> dict:
            """
            Get the changes needed between the current and desired SNMP user configuration.

            Args:
                current (dict): The current SNMP user configuration.
                desired (dict): The desired SNMP user configuration.

            Returns:
                dict: The changes needed to update the current configuration to match the desired configuration.
            """

            changes_needed: dict = dict()

            update_passphrase: str = self.params['update_passphrase']

            for key in desired.keys():

                if key in ['auth_passphrase', 'priv_passphrase'] and update_passphrase == 'on_create':
                    continue

                if key in ['auth_protocol', 'priv_protocol']:

                    if key not in current or current[key].lower() != desired[key].lower():
                        changes_needed[key] = desired[key]

                    continue

                if key not in current or current[key] != desired[key]:
                    changes_needed[key] = desired[key]

            changes_needed['index'] = current['index']

            return changes_needed

        def update_snmp_user(self, changes: dict) -> None:
            """
            Update an existing SNMP user in the Redfish client.

            Args:
                changes (dict): The changes to apply to the SNMP user configuration.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            snmp_users_uri: str = self.get_manager_snmp_users_uri()
            snmp_user_uri: str = snmp_users_uri + '/' + str(changes['index'])

            payload: dict = dict()

            if 'auth_protocol' in changes:
                payload['AuthProtocol'] = changes['auth_protocol'].upper()

            if 'auth_passphrase' in changes:
                payload['AuthPassphrase'] = changes['auth_passphrase']

            if 'priv_protocol' in changes:
                payload['PrivacyProtocol'] = changes['priv_protocol'].upper()

            if 'priv_passphrase' in changes:
                payload['PrivacyPassphrase'] = changes['priv_passphrase']

            if 'user_engine_id' in changes:
                payload['UserEngineID'] = changes['user_engine_id']

            try:
                response: RestResponse = self.client.patch(snmp_user_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error occurred when updating SNMP user', exception=to_native(e)))

            if response.status not in [200, 201, 204]:
                self.handle_error(iLOModuleError(message='Failed to update SNMP user'))

        def delete_snmp_user(self, user: dict) -> None:
            """
            Delete an existing SNMP user in the Redfish client.

            Args:
                user (dict): The SNMP user configuration to delete.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            snmp_users_uri: str = self.get_manager_snmp_users_uri()
            snmp_user_uri: str = snmp_users_uri + '/' + str(user['index'])

            try:
                response: RestResponse = self.client.delete(snmp_user_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error occurred when deleting SNMP user', exception=to_native(e)))

            if response.status not in [200, 204]:
                self.handle_error(iLOModuleError(message='Failed to delete SNMP user'))


from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOSnmpUserModule = iLOSnmpUserModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    security_name: str = module.params['security_name']
    state: str = module.params['state']

    if state == 'absent':
        unsupported_params: List[str] = []

        if module.params.get('auth_protocol', None) is not None:
            unsupported_params.append('auth_protocol')

        if module.params.get('auth_passphrase', None) is not None:
            unsupported_params.append('auth_passphrase')

        if module.params.get('priv_protocol', None) is not None:
            unsupported_params.append('priv_protocol')

        if module.params.get('priv_passphrase', None) is not None:
            unsupported_params.append('priv_passphrase')

        if module.params.get('user_engine_id', None) is not None:
            unsupported_params.append('user_engine_id')

        if len(unsupported_params) > 0:
            module.fail_json(
                msg=f'The following parameters are not supported when state is set to absent: {", ".join(unsupported_params)}'
            )

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    current_user: Optional[dict] = module.get_snmp_user(security_name)

    if current_user is None:
        result['diff']['before']['user'] = None
    else:
        result['diff']['before']['user'] = current_user.copy()

    if state == 'present':

        desired_config: dict = module.get_desired_config()

        if current_user is None:

            returned_user: dict = desired_config.copy()
            returned_user['index'] = module.get_next_snmp_user_index()

            if 'auth_protocol' not in returned_user:
                returned_user['auth_protocol'] = 'sha'

            if 'priv_protocol' not in returned_user:
                returned_user['priv_protocol'] = 'aes'

            if 'user_engine_id' not in returned_user:
                returned_user['user_engine_id'] = ''

            returned_user['auth_passphrase'] = '*'
            returned_user['priv_passphrase'] = '*'

            result['changed'] = True
            result['diff']['after']['user'] = returned_user
            result.update(returned_user)

            if not module.check_mode:
                module.create_snmp_user(desired_config)

        else:
            changes_needed: dict = module.get_changes_needed(current_user, desired_config)

            if len(changes_needed) > 0:

                returned_user: dict = current_user.copy()
                returned_user.update(changes_needed)

                if 'auth_protocol' in returned_user:
                    returned_user['auth_protocol'] = returned_user['auth_protocol'].lower()

                if 'auth_passphrase' in returned_user:
                    returned_user['auth_passphrase'] = '*'

                if 'priv_protocol' in returned_user:
                    returned_user['priv_protocol'] = returned_user['priv_protocol'].lower()

                if 'priv_passphrase' in returned_user:
                    returned_user['priv_passphrase'] = '*'

                result['changed'] = True
                result['diff']['after']['user'] = returned_user
                result.update(returned_user)

                if not module.check_mode:
                    changes_needed['index'] = current_user['index']
                    module.update_snmp_user(changes_needed)
            else:
                result['diff']['after']['user'] = current_user.copy()
                result.update(current_user)

    elif state == 'absent':

        result['diff']['after']['user'] = None

        if current_user is not None:

            result['changed'] = True

            if not module.check_mode:
                module.delete_snmp_user(current_user)

    module.logout()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
