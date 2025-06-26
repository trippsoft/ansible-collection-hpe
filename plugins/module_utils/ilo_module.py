# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import traceback

from .ilo_module_error import iLOModuleError

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from typing import List, Optional

COMMON_ARGSPEC: dict = dict(
    base_url=dict(type='str', required=True),
    username=dict(type='str', required=True),
    password=dict(type='str', required=True, no_log=True)
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

            managers_uri: str = '/redfish/v1/Managers'

            try:
                response: RestResponse = self.client.get(managers_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {managers_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {managers_uri}'))

            if 'Members' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Members\' not found in {managers_uri}'))

            members: List[dict] = response.dict['Members']

            if len(members) == 0:
                self.handle_error(iLOModuleError(message=f'Empty \'Members\' found in {managers_uri}'))

            member: dict = members[0]

            if '@odata.id' not in member:
                self.handle_error(iLOModuleError(message='No \'@odata.id\' found in manager member'))

            return member['@odata.id']

        def get_manager_date_time_service_uri(self) -> str:
            """
            Get the manager date time service URI from the Redfish client.

            Returns:
                str: The manager date time service URI.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_uri: str = self.get_manager_uri()

            try:
                response: RestResponse = self.client.get(manager_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {manager_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {manager_uri}'))

            if 'Oem' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Oem\' not found in {manager_uri}'))

            oem: dict = response.dict['Oem']

            if 'Hpe' not in oem:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe\' not found in {manager_uri}'))

            hpe: dict = oem['Hpe']

            if 'Links' not in hpe:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.Links\' not found in {manager_uri}'))

            links: dict = hpe['Links']

            if 'DateTimeService' not in links:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.Links.DateTimeService\' not found in {manager_uri}'))

            date_time: dict = links['DateTimeService']

            if '@odata.id' not in date_time:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.Links.DateTimeService.@odata.id\' not found in {manager_uri}'))

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
                self.handle_error(iLOModuleError(message=f'Error retrieving {manager_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {manager_uri}'))

            if 'EthernetInterfaces' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'EthernetInterfaces\' not found in {manager_uri}'))

            ethernet_interfaces: dict = response.dict['EthernetInterfaces']

            if '@odata.id' not in ethernet_interfaces:
                self.handle_error(iLOModuleError(message=f'\'EthernetInterfaces.@odata.id\' not found in {manager_uri}'))

            manager_ethernet_collection_uri: str = ethernet_interfaces['@odata.id']

            try:
                response = self.client.get(manager_ethernet_collection_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {manager_ethernet_collection_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {manager_ethernet_collection_uri}'))

            if 'Members' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Members\' not found in {manager_ethernet_collection_uri}'))

            members: List[dict] = response.dict['Members']

            if len(members) == 0:
                self.handle_error(iLOModuleError(message=f'Empty \'Members\' found in {manager_ethernet_collection_uri}'))

            if '@odata.id' not in members[0]:
                self.handle_error(iLOModuleError(message='No \'@odata.id\' found in manager Ethernet member'))

            return members[0]['@odata.id']

        def get_manager_security_service_uri(self) -> str:
            """
            Get the manager security service URI from the Redfish client.

            Returns:
                str: The manager security service URI.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_uri: str = self.get_manager_uri()

            try:
                response: RestResponse = self.client.get(manager_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {manager_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {manager_uri}'))

            if 'Oem' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Oem\' not found in {manager_uri}'))

            oem: dict = response.dict['Oem']

            if 'Hpe' not in oem:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe\' not found in {manager_uri}'))

            hpe: dict = oem['Hpe']

            if 'Links' not in hpe:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.Links\' not found in {manager_uri}'))

            links: dict = hpe['Links']

            if 'SecurityService' not in links:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.Links.SecurityService\' not found in {manager_uri}'))

            security_service: dict = links['SecurityService']

            if '@odata.id' not in security_service:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.Links.SecurityService.@odata.id\' not found in {manager_uri}'))

            return security_service['@odata.id']

        def get_manager_security_https_cert_uri(self) -> str:
            """
            Get the manager security HTTPS certificate URI from the Redfish client.

            Returns:
                str: The manager security HTTPS certificate URI.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            security_service_uri: str = self.get_manager_security_service_uri()

            try:
                response: RestResponse = self.client.get(security_service_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {security_service_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {security_service_uri}'))

            if 'Links' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Links\' not found in {security_service_uri}'))

            links: dict = response.dict['Links']

            if 'HttpsCert' not in links:
                self.handle_error(iLOModuleError(message=f'\'Links.HttpsCert\' not found in {security_service_uri}'))

            https_certificate: dict = links['HttpsCert']

            if '@odata.id' not in https_certificate:
                self.handle_error(iLOModuleError(message=f'\'Links.HttpsCert.@odata.id\' not found in {security_service_uri}'))

            return https_certificate['@odata.id']

        def get_manager_snmp_service_uri(self) -> str:
            """
            Get the manager SNMP service URI from the Redfish client.

            Returns:
                str: The manager SNMP service URI.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            manager_uri: str = self.get_manager_uri()

            try:
                response: RestResponse = self.client.get(manager_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {manager_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {manager_uri}'))

            if 'Oem' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'Oem\' not found in {manager_uri}'))

            oem: dict = response.dict['Oem']

            if 'Hpe' not in oem:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe\' not found in {manager_uri}'))

            hpe: dict = oem['Hpe']

            if 'Links' not in hpe:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.Links\' not found in {manager_uri}'))

            links: dict = hpe['Links']

            if 'SNMPService' not in links:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.Links.SNMPService\' not found in {manager_uri}'))

            snmp_service: dict = links['SNMPService']

            if '@odata.id' not in snmp_service:
                self.handle_error(iLOModuleError(message=f'\'Oem.Hpe.Links.SNMPService.@odata.id\' not found in {manager_uri}'))

            return snmp_service['@odata.id']

        def get_manager_snmp_users_uri(self) -> str:
            """
            Get the manager SNMP users URI from the Redfish client.

            Returns:
                str: The manager SNMP users URI.
            """

            if not self.client:
                self.fail_json(msg='Redfish client is not initialized')

            snmp_service_uri: str = self.get_manager_snmp_service_uri()

            try:
                response: RestResponse = self.client.get(snmp_service_uri)
            except Exception as e:
                self.handle_error(iLOModuleError(message=f'Error retrieving {snmp_service_uri}', exception=to_native(e)))

            if response.status != 200:
                self.handle_error(iLOModuleError(message=f'Failed to retrieve {snmp_service_uri}'))

            if 'SNMPUsers' not in response.dict:
                self.handle_error(iLOModuleError(message=f'\'SNMPUsers\' not found in {snmp_service_uri}'))

            snmp_users: dict = response.dict['SNMPUsers']

            if '@odata.id' not in snmp_users:
                self.handle_error(iLOModuleError(message=f'\'SNMPUsers.@odata.id\' not found in {snmp_service_uri}'))

            return snmp_users['@odata.id']
