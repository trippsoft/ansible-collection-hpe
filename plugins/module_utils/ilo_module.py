# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

import traceback

from .ilo_module_error import iLOModuleError

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from typing import List, Optional

COMMON_ARGSPEC: dict = dict(
    base_url=dict(type='str', required=True),
    username=dict(type='str', required=True),
    password=dict(type='str', required=True, no_log=True),
)

try:
    import redfish
    from redfish.rest.containers import RestResponse
except ImportError:
    HAS_REDFISH: bool = False
    REDFISH_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    class iLOModule(AnsibleModule):
        """
        Extends iLOModule to simplify the creation of iLO modules.
        """

        def __init__(self, *args, argument_spec: Optional[dict], **kwargs) -> None:

            if argument_spec is None:
                argument_spec = dict()

            argspec: dict = COMMON_ARGSPEC.copy()
            argspec.update(argument_spec)

            super().__init__(*args, argument_spec=argspec, **kwargs)

else:
    HAS_REDFISH: bool = True
    REDFISH_IMPORT_ERROR: Optional[str] = None

    class iLOModule(AnsibleModule):
        """
        Extends AnsibleModule to simplify the creation of iLO modules.
        """

        client: redfish.RedfishClient

        def __init__(self, *args, argument_spec: Optional[dict] = None, **kwargs) -> None:

            if argument_spec is None:
                argument_spec = dict()

            argspec: dict = COMMON_ARGSPEC.copy()
            argspec.update(argument_spec)

            super().__init__(*args, argument_spec=argspec, **kwargs)

        def handle_error(self, error) -> None:
            """
            Handle an error, if it occurred, in the module.

            Args:
                error (Any): A value that could be a VaultModuleError.
            """

            if isinstance(error, iLOModuleError):
                self.logout()
                self.fail_json(msg=error.message, exception=error.exception)

        def initialize_client(self) -> None:
            """
            Initialize the Redfish client.
            """

            self.client = redfish.RedfishClient(
                base_url=self.params['base_url'],
                username=self.params['username'],
                password=self.params['password'],
            )

            try:
                self.client.login()
            except Exception as e:
                self.fail_json(msg='Failed to login to iLO', exception=to_native(e))

        def logout(self) -> None:
            """
            Logout from the Redfish client.
            """

            if self.client:
                try:
                    self.client.logout()
                except Exception as e:
                    self.fail_json(msg='Failed to logout from iLO', exception=to_native(e))

        def get_manager_uri(self) -> str:
            """
            Get the manager URI from the Redfish client.

            Returns:
                str: The manager URI.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            try:
                response: RestResponse = self.client.get('/redfish/v1/Managers')
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error retrieving manager URI', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message='Failed to retrieve manager collection'))

            if 'Members' not in response.dict:
                self.handle_error(iLOModuleError(message='No members found in manager collection'))

            members: List[dict] = response.dict['Members']

            if len(members) == 0:
                self.handle_error(iLOModuleError(message='Empty members found in manager collection'))

            member: dict = members[0]

            if '@odata.id' not in member:
                self.handle_error(iLOModuleError(message='No @odata.id found in manager member'))

            return member['@odata.id']

        def get_manager_date_time_uri(self) -> str:
            """
            Get the manager date time URI from the Redfish client.

            Returns:
                str: The manager date time URI.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_uri: str = self.get_manager_uri()

            try:
                response: RestResponse = self.client.get(manager_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error retrieving manager date time URI', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message='Failed to retrieve manager date time URI'))

            if 'Oem' not in response.dict:
                self.handle_error(iLOModuleError(message='No Oem found in manager'))

            oem: dict = response.dict['Oem']

            if 'Hpe' not in oem:
                self.handle_error(iLOModuleError(message='No Hpe found in manager Oem'))

            hpe: dict = oem['Hpe']

            if 'Links' not in hpe:
                self.handle_error(iLOModuleError(message='No Links found in manager Hpe'))

            links: dict = hpe['Links']

            if 'DateTime' not in links:
                self.handle_error(iLOModuleError(message='No DateTime found in manager Hpe Links'))

            date_time: dict = links['DateTime']

            if '@odata.id' not in date_time:
                self.handle_error(iLOModuleError(message='No @odata.id found in manager Hpe Links DateTime'))

            return date_time['@odata.id']

        def get_manager_ethernet_uri(self) -> str:
            """
            Get the manager Ethernet URI from the Redfish client.

            Returns:
                str: The manager Ethernet URI.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_uri: str = self.get_manager_uri()

            try:
                response: RestResponse = self.client.get(manager_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error retrieving manager Ethernet URI', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message='Failed to retrieve manager Ethernet URI'))

            if 'EthernetInterfaces' not in response.dict:
                self.handle_error(iLOModuleError(message='No EthernetInterfaces found in manager'))

            ethernet_interfaces: dict = response.dict['EthernetInterfaces']

            if '@odata.id' not in ethernet_interfaces:
                self.handle_error(iLOModuleError(message='No @odata.id found in manager EthernetInterfaces'))

            manager_ethernet_collection_uri: str = ethernet_interfaces['@odata.id']

            try:
                response = self.client.get(manager_ethernet_collection_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message='Error retrieving manager Ethernet URI', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message='Failed to retrieve manager Ethernet URI'))

            if 'Members' not in response.dict:
                self.handle_error(iLOModuleError(message='No members found in manager Ethernet collection'))

            members: List[dict] = response.dict['Members']

            if len(members) == 0:
                self.handle_error(iLOModuleError(message='Empty members found in manager Ethernet collection'))

            return members[0]['@odata.id']
