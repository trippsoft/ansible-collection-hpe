#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: ilo_time_zone
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures iLO time zone settings.
description:
  - >-
    This module configures the time zone settings for an HPE iLO device.
extends_documentation_fragment:
  - trippsc2.hpe.action_group
  - trippsc2.hpe.check_mode
  - trippsc2.hpe.common
options:
  name:
    type: str
    required: false
    aliases:
      - time_zone
    description:
      - The name of the time zone to configure.
      - This should be a valid time zone name in HPE iLO style (e.g., "Bogota, Lima, Quito, Eastern Time(US & Canada)").
      - This is mutually exclusive with O(index).
      - One of O(name) or O(index) must be provided.
  index:
    type: int
    required: false
    aliases:
      - time_zone_index
    description:
      - The index of the time zone to configure.
      - This is mutually exclusive with O(name).
      - One of O(name) or O(index) must be provided.
"""

EXAMPLES = r"""
- name: Configure iLO time zone by name
  trippsc2.hpe.ilo_time_zone:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    name: 'Bogota, Lima, Quito, Eastern Time(US & Canada)'

- name: Configure iLO time zone by index
  trippsc2.hpe.ilo_time_zone:
    url_base: '192.0.2.200'
    username: 'Administrator'
    password: 'password'
    index: 8
"""

RETURN = r"""
time_zone:
  type: dict
  returned: always
  description:
    - The configured time zone for the iLO device.
    - Contains the relevant time zone information.
  contains:
    name:
      type: str
      returned: always
      description:
        - The name of the configured time zone.
    index:
      type: int
      returned: always
      description:
        - The index of the configured time zone.
    utc_offset:
      type: str
      returned: always
      description:
        - The UTC offset of the configured time zone.
    value:
      type: str
      returned: always
      description:
        - The value of the configured time zone.
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ..module_utils.ilo_module import iLOModule
from ..module_utils.ilo_module_error import iLOModuleError

from typing import List, Optional

ARGSPEC: dict = dict(
    name=dict(type='str', required=False, aliases=['time_zone']),
    index=dict(type='int', required=False, aliases=['time_zone_index'])
)

try:
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    class iLOTimeZoneModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO time zone modules.
        """

        def __init__(self, *args, **kwargs) -> None:

            super().__init__(
                *args,
                argument_spec=ARGSPEC.copy(),
                mutually_exclusive=[
                    ('name', 'index')
                ],
                required_one_of=[
                    ('name', 'index')
                ],
                supports_check_mode=True,
                **kwargs
            )

        def get_time_zone(self) -> dict:
            """
            Get the current time zone from the Redfish client.

            Returns:
                dict: The current time zone information.
            """

            pass

        def format_time_zone(self, time_zone: dict) -> dict:
            """
            Format the iLO time zone information into the desired structure.

            Args:
                time_zone (dict): The time zone information to format.

            Returns:
                dict: The formatted time zone information.
            """

            return dict(
                name=time_zone['Name'],
                index=time_zone['Index'],
                utc_offset=time_zone['UTCOffset'],
                value=time_zone['Value']
            )

        def match_expected_time_zone(self, index: Optional[int], name: Optional[str]) -> Optional[dict]:
            """
            Match the expected time zone based on the provided index or name.

            Args:
                index (Optional[int]): The index of the time zone to match.
                name (Optional[str]): The name of the time zone to match.

            Returns:
                dict: The matching time zone information, or None if not found.
            """

            discard = index
            discard = name
            pass

        def set_time_zone(self, index: int) -> None:
            """
            Set the iLO time zone to the specified index.

            Args:
                index (int): The index of the time zone to set.
            """

            discard = index
            pass

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOTimeZoneModule(iLOModule):
        """
        Extends iLOModule to simplify the creation of iLO time zone modules.
        """

        def __init__(self, *args, **kwargs) -> None:

            super().__init__(
                *args,
                argument_spec=ARGSPEC.copy(),
                mutually_exclusive=[
                    ('name', 'index')
                ],
                required_one_of=[
                    ('name', 'index')
                ],
                supports_check_mode=True,
                **kwargs)

        def get_time_zone(self) -> dict:
            """
            Get the current time zone from the Redfish client.

            Returns:
                dict: The current time zone information.
            """

            date_time_service_uri: str = self.get_manager_date_time_service_uri()

            try:
                response: RestResponse = self.client.get(date_time_service_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f"Error retrieving {date_time_service_uri}", exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f"Failed to retrieve {date_time_service_uri}"))

            if 'TimeZone' not in response.dict:
                self.handle_error(iLOModuleError(message=f"\'TimeZone\' is not found in {date_time_service_uri}"))

            return self.format_time_zone(response.dict['TimeZone'])

        def format_time_zone(self, time_zone: dict) -> dict:
            """
            Format the iLO time zone information into the desired structure.

            Args:
                time_zone (dict): The time zone information to format.

            Returns:
                dict: The formatted time zone information.
            """

            return dict(
                name=time_zone['Name'],
                index=time_zone['Index'],
                utc_offset=time_zone['UTCOffset'],
                value=time_zone['Value']
            )

        def match_expected_time_zone(self, index: Optional[int], name: Optional[str]) -> Optional[dict]:
            """
            Match the expected time zone based on the provided index or name.

            Args:
                index (Optional[int]): The index of the time zone to match.
                name (Optional[str]): The name of the time zone to match.

            Returns:
                dict: The matching time zone information, or None if not found.
            """

            date_time_service_uri: str = self.get_manager_date_time_service_uri()

            try:
                response: RestResponse = self.client.get(date_time_service_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f"Error retrieving {date_time_service_uri}", exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f"Failed to retrieve {date_time_service_uri}"))

            if 'TimeZoneList' not in response.dict:
                self.handle_error(iLOModuleError(message=f"\'TimeZoneList\' is not found in {date_time_service_uri}"))

            time_zones: List[dict] = response.dict['TimeZoneList']

            for time_zone in time_zones:
                if index is not None and time_zone['Index'] == index:
                    return [self.format_time_zone(time_zone)]
                elif name is not None and time_zone['Name'] == name:
                    return [self.format_time_zone(time_zone)]

            return None

        def set_time_zone(self, index: int) -> None:
            """
            Set the iLO time zone to the specified index.

            Args:
                index (int): The index of the time zone to set.
            """

            date_time_service_uri: str = self.get_manager_date_time_service_uri()
            payload: dict = dict(
                TimeZone=dict(
                    Index=index
                )
            )

            try:
                response: RestResponse = self.client.patch(date_time_service_uri, payload)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f"Error setting time zone to {index}", exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f"Failed to set time zone to {index}"))

from ansible.module_utils.basic import missing_required_lib


def run_module() -> None:

    module: iLOTimeZoneModule = iLOTimeZoneModule()

    if not HAS_REDFISH:
        module.fail_json(
            msg=missing_required_lib('redfish'),
            exception=REDFISH_IMPORT_ERROR
        )

    name: Optional[str] = module.params.get('name', None)
    index: Optional[int] = module.params.get('index', None)

    module.initialize_client()

    result: dict = dict(
        changed=False,
        diff=dict(before=dict(), after=dict())
    )

    current_time_zone: dict = module.get_time_zone()

    result["diff"]["before"]["time_zone"] = current_time_zone

    if ((name is not None and current_time_zone['name'] == name) or (index is not None and current_time_zone['index'] == index)):

        result["diff"]["after"]["time_zone"] = current_time_zone
        result["time_zone"] = current_time_zone

    else:

        expected_time_zone: Optional[dict] = module.match_expected_time_zone(index, name)

        if expected_time_zone is None:
            module.handle_error(iLOModuleError(message='The specified time zone does not exist on the iLO device'))

        result["changed"] = True
        result["diff"]["after"]["time_zone"] = expected_time_zone
        result["time_zone"] = expected_time_zone

        if not module.check_mode:
            module.set_time_zone(expected_time_zone['index'])

    module.logout()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
