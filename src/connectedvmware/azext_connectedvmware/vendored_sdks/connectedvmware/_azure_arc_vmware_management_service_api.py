# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from copy import deepcopy
from typing import TYPE_CHECKING

from msrest import Deserializer, Serializer

from azure.mgmt.core import ARMPipelineClient

from . import models
from ._configuration import AzureArcVMwareManagementServiceAPIConfiguration
from .operations import AzureArcVMwareManagementServiceAPIOperationsMixin, ClustersOperations, DatastoresOperations, GuestAgentsOperations, HostsOperations, HybridIdentityMetadataOperations, InventoryItemsOperations, MachineExtensionsOperations, Operations, ResourcePoolsOperations, VCentersOperations, VMInstanceGuestAgentsOperations, VirtualMachineInstancesOperations, VirtualMachineTemplatesOperations, VirtualMachinesOperations, VirtualNetworksOperations, VmInstanceHybridIdentityMetadataOperations

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

    from azure.core.credentials import TokenCredential
    from azure.core.rest import HttpRequest, HttpResponse

class AzureArcVMwareManagementServiceAPI(AzureArcVMwareManagementServiceAPIOperationsMixin):    # pylint: disable=too-many-instance-attributes
    """Self service experience for VMware.

    :ivar operations: Operations operations
    :vartype operations: azure_arc_vmware_management_service_api.operations.Operations
    :ivar virtual_machines: VirtualMachinesOperations operations
    :vartype virtual_machines:
     azure_arc_vmware_management_service_api.operations.VirtualMachinesOperations
    :ivar resource_pools: ResourcePoolsOperations operations
    :vartype resource_pools:
     azure_arc_vmware_management_service_api.operations.ResourcePoolsOperations
    :ivar clusters: ClustersOperations operations
    :vartype clusters: azure_arc_vmware_management_service_api.operations.ClustersOperations
    :ivar hosts: HostsOperations operations
    :vartype hosts: azure_arc_vmware_management_service_api.operations.HostsOperations
    :ivar datastores: DatastoresOperations operations
    :vartype datastores: azure_arc_vmware_management_service_api.operations.DatastoresOperations
    :ivar vcenters: VCentersOperations operations
    :vartype vcenters: azure_arc_vmware_management_service_api.operations.VCentersOperations
    :ivar virtual_machine_templates: VirtualMachineTemplatesOperations operations
    :vartype virtual_machine_templates:
     azure_arc_vmware_management_service_api.operations.VirtualMachineTemplatesOperations
    :ivar virtual_networks: VirtualNetworksOperations operations
    :vartype virtual_networks:
     azure_arc_vmware_management_service_api.operations.VirtualNetworksOperations
    :ivar inventory_items: InventoryItemsOperations operations
    :vartype inventory_items:
     azure_arc_vmware_management_service_api.operations.InventoryItemsOperations
    :ivar hybrid_identity_metadata: HybridIdentityMetadataOperations operations
    :vartype hybrid_identity_metadata:
     azure_arc_vmware_management_service_api.operations.HybridIdentityMetadataOperations
    :ivar machine_extensions: MachineExtensionsOperations operations
    :vartype machine_extensions:
     azure_arc_vmware_management_service_api.operations.MachineExtensionsOperations
    :ivar guest_agents: GuestAgentsOperations operations
    :vartype guest_agents: azure_arc_vmware_management_service_api.operations.GuestAgentsOperations
    :ivar virtual_machine_instances: VirtualMachineInstancesOperations operations
    :vartype virtual_machine_instances:
     azure_arc_vmware_management_service_api.operations.VirtualMachineInstancesOperations
    :ivar vm_instance_hybrid_identity_metadata: VmInstanceHybridIdentityMetadataOperations
     operations
    :vartype vm_instance_hybrid_identity_metadata:
     azure_arc_vmware_management_service_api.operations.VmInstanceHybridIdentityMetadataOperations
    :ivar vm_instance_guest_agents: VMInstanceGuestAgentsOperations operations
    :vartype vm_instance_guest_agents:
     azure_arc_vmware_management_service_api.operations.VMInstanceGuestAgentsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: The Subscription ID.
    :type subscription_id: str
    :param base_url: Service URL. Default value is 'https://management.azure.com'.
    :type base_url: str
    :keyword api_version: Api Version. The default value is "2023-03-01-preview". Note that
     overriding this default value may result in unsupported behavior.
    :paramtype api_version: str
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no
     Retry-After header is present.
    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        subscription_id,  # type: str
        base_url="https://management.azure.com",  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        self._config = AzureArcVMwareManagementServiceAPIConfiguration(credential=credential, subscription_id=subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)
        self._serialize.client_side_validation = False
        self.operations = Operations(self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machines = VirtualMachinesOperations(self._client, self._config, self._serialize, self._deserialize)
        self.resource_pools = ResourcePoolsOperations(self._client, self._config, self._serialize, self._deserialize)
        self.clusters = ClustersOperations(self._client, self._config, self._serialize, self._deserialize)
        self.hosts = HostsOperations(self._client, self._config, self._serialize, self._deserialize)
        self.datastores = DatastoresOperations(self._client, self._config, self._serialize, self._deserialize)
        self.vcenters = VCentersOperations(self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machine_templates = VirtualMachineTemplatesOperations(self._client, self._config, self._serialize, self._deserialize)
        self.virtual_networks = VirtualNetworksOperations(self._client, self._config, self._serialize, self._deserialize)
        self.inventory_items = InventoryItemsOperations(self._client, self._config, self._serialize, self._deserialize)
        self.hybrid_identity_metadata = HybridIdentityMetadataOperations(self._client, self._config, self._serialize, self._deserialize)
        self.machine_extensions = MachineExtensionsOperations(self._client, self._config, self._serialize, self._deserialize)
        self.guest_agents = GuestAgentsOperations(self._client, self._config, self._serialize, self._deserialize)
        self.virtual_machine_instances = VirtualMachineInstancesOperations(self._client, self._config, self._serialize, self._deserialize)
        self.vm_instance_hybrid_identity_metadata = VmInstanceHybridIdentityMetadataOperations(self._client, self._config, self._serialize, self._deserialize)
        self.vm_instance_guest_agents = VMInstanceGuestAgentsOperations(self._client, self._config, self._serialize, self._deserialize)


    def _send_request(
        self,
        request,  # type: HttpRequest
        **kwargs  # type: Any
    ):
        # type: (...) -> HttpResponse
        """Runs the network request through the client's chained policies.

        >>> from azure.core.rest import HttpRequest
        >>> request = HttpRequest("GET", "https://www.example.org/")
        <HttpRequest [GET], url: 'https://www.example.org/'>
        >>> response = client._send_request(request)
        <HttpResponse: 200 OK>

        For more information on this code flow, see https://aka.ms/azsdk/python/protocol/quickstart

        :param request: The network request you want to make. Required.
        :type request: ~azure.core.rest.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to False.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.rest.HttpResponse
        """

        request_copy = deepcopy(request)
        request_copy.url = self._client.format_url(request_copy.url)
        return self._client.send_request(request_copy, **kwargs)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> AzureArcVMwareManagementServiceAPI
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
