# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class Acl(msrest.serialization.Model):
    """Access Control List (ACL) for an iSCSI Target; defines LUN masking policy.

    All required parameters must be populated in order to send to Azure.

    :param initiator_iqn: Required. iSCSI initiator IQN (iSCSI Qualified Name); example:
     "iqn.2005-03.org.iscsi:client".
    :type initiator_iqn: str
    :param mapped_luns: Required. List of LUN names mapped to the ACL.
    :type mapped_luns: list[str]
    """

    _validation = {
        'initiator_iqn': {'required': True},
        'mapped_luns': {'required': True},
    }

    _attribute_map = {
        'initiator_iqn': {'key': 'initiatorIqn', 'type': 'str'},
        'mapped_luns': {'key': 'mappedLuns', 'type': '[str]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Acl, self).__init__(**kwargs)
        self.initiator_iqn = kwargs['initiator_iqn']
        self.mapped_luns = kwargs['mapped_luns']


class Disk(msrest.serialization.Model):
    """Azure Managed Disk to attach to the Disk Pool.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Unique Azure Resource ID of the Managed Disk.
    :type id: str
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Disk, self).__init__(**kwargs)
        self.id = kwargs['id']


class Resource(msrest.serialization.Model):
    """ARM resource model definition.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Ex- Microsoft.Compute/virtualMachines or
     Microsoft.Storage/storageAccounts.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class TrackedResource(Resource):
    """The resource model definition for a ARM tracked top level resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Ex- Microsoft.Compute/virtualMachines or
     Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives.
    :type location: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TrackedResource, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.location = kwargs['location']


class DiskPool(TrackedResource):
    """Response for Disk Pool request.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Ex- Microsoft.Compute/virtualMachines or
     Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives.
    :type location: str
    :ivar system_data: Resource metadata required by ARM RPC.
    :vartype system_data: ~storage_pool_management.models.SystemMetadata
    :ivar provisioning_state: Required. State of the operation on the resource. Possible values
     include: "Invalid", "Succeeded", "Failed", "Canceled", "Pending", "Creating", "Updating",
     "Deleting".
    :vartype provisioning_state: str or ~storage_pool_management.models.ProvisioningStates
    :param availability_zones: Required. Logical zone for Disk Pool resource; example: ["1"].
    :type availability_zones: list[str]
    :param status: Required. Operational status of the Disk Pool. Possible values include:
     "Invalid", "Unknown", "Healthy", "Unhealthy", "Updating", "Running", "Stopped", "Stopped
     (deallocated)".
    :type status: str or ~storage_pool_management.models.OperationalStatus
    :param disks: List of Azure Managed Disks to attach to a Disk Pool.
    :type disks: list[~storage_pool_management.models.Disk]
    :param subnet_id: Required. Azure Resource ID of a Subnet for the Disk Pool.
    :type subnet_id: str
    :param additional_capabilities: List of additional capabilities for Disk Pool.
    :type additional_capabilities: list[str]
    :param name_sku_name: Sku name.
    :type name_sku_name: str
    :param tier: Sku tier.
    :type tier: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'system_data': {'readonly': True},
        'provisioning_state': {'required': True, 'readonly': True},
        'availability_zones': {'required': True},
        'status': {'required': True},
        'subnet_id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'system_data': {'key': 'systemData', 'type': 'SystemMetadata'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'availability_zones': {'key': 'properties.availabilityZones', 'type': '[str]'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'disks': {'key': 'properties.disks', 'type': '[Disk]'},
        'subnet_id': {'key': 'properties.subnetId', 'type': 'str'},
        'additional_capabilities': {'key': 'properties.additionalCapabilities', 'type': '[str]'},
        'name_sku_name': {'key': 'sku.name', 'type': 'str'},
        'tier': {'key': 'sku.tier', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DiskPool, self).__init__(**kwargs)
        self.system_data = None
        self.provisioning_state = None
        self.availability_zones = kwargs['availability_zones']
        self.status = kwargs['status']
        self.disks = kwargs.get('disks', None)
        self.subnet_id = kwargs['subnet_id']
        self.additional_capabilities = kwargs.get('additional_capabilities', None)
        self.name_sku_name = kwargs.get('name_sku_name', None)
        self.tier = kwargs.get('tier', None)


class DiskPoolCreate(msrest.serialization.Model):
    """Request payload for create or update Disk Pool request.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param sku: Required. Determines the SKU of the Disk Pool.
    :type sku: ~storage_pool_management.models.Sku
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives.
    :type location: str
    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Ex- Microsoft.Compute/virtualMachines or
     Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param availability_zones: Logical zone for Disk Pool resource; example: ["1"].
    :type availability_zones: list[str]
    :param disks: List of Azure Managed Disks to attach to a Disk Pool.
    :type disks: list[~storage_pool_management.models.Disk]
    :param subnet_id: Required. Azure Resource ID of a Subnet for the Disk Pool.
    :type subnet_id: str
    :param additional_capabilities: List of additional capabilities for a Disk Pool.
    :type additional_capabilities: list[str]
    """

    _validation = {
        'sku': {'required': True},
        'location': {'required': True},
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'subnet_id': {'required': True},
    }

    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'Sku'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'availability_zones': {'key': 'properties.availabilityZones', 'type': '[str]'},
        'disks': {'key': 'properties.disks', 'type': '[Disk]'},
        'subnet_id': {'key': 'properties.subnetId', 'type': 'str'},
        'additional_capabilities': {'key': 'properties.additionalCapabilities', 'type': '[str]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DiskPoolCreate, self).__init__(**kwargs)
        self.sku = kwargs['sku']
        self.tags = kwargs.get('tags', None)
        self.location = kwargs['location']
        self.id = None
        self.name = None
        self.type = None
        self.availability_zones = kwargs.get('availability_zones', None)
        self.disks = kwargs.get('disks', None)
        self.subnet_id = kwargs['subnet_id']
        self.additional_capabilities = kwargs.get('additional_capabilities', None)


class DiskPoolListResult(msrest.serialization.Model):
    """List of Disk Pools.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. An array of Disk pool objects.
    :type value: list[~storage_pool_management.models.DiskPool]
    :ivar next_link: URI to fetch the next section of the paginated response.
    :vartype next_link: str
    """

    _validation = {
        'value': {'required': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[DiskPool]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DiskPoolListResult, self).__init__(**kwargs)
        self.value = kwargs['value']
        self.next_link = None


class DiskPoolUpdate(msrest.serialization.Model):
    """Request payload for Update Disk Pool request.

    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param disks: List of Azure Managed Disks to attach to a Disk Pool.
    :type disks: list[~storage_pool_management.models.Disk]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'disks': {'key': 'properties.disks', 'type': '[Disk]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DiskPoolUpdate, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.disks = kwargs.get('disks', None)


class DiskPoolZoneInfo(msrest.serialization.Model):
    """Disk Pool Sku Details.

    :param availability_zones: Logical zone for Disk Pool resource; example: ["1"].
    :type availability_zones: list[str]
    :param additional_capabilities: List of additional capabilities for Disk Pool.
    :type additional_capabilities: list[str]
    :param sku: Determines the SKU of VM deployed for Disk Pool.
    :type sku: ~storage_pool_management.models.Sku
    """

    _attribute_map = {
        'availability_zones': {'key': 'availabilityZones', 'type': '[str]'},
        'additional_capabilities': {'key': 'additionalCapabilities', 'type': '[str]'},
        'sku': {'key': 'sku', 'type': 'Sku'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DiskPoolZoneInfo, self).__init__(**kwargs)
        self.availability_zones = kwargs.get('availability_zones', None)
        self.additional_capabilities = kwargs.get('additional_capabilities', None)
        self.sku = kwargs.get('sku', None)


class DiskPoolZoneListResult(msrest.serialization.Model):
    """List Disk Pool skus operation response.

    :param value: The list of Disk Pool Skus.
    :type value: list[~storage_pool_management.models.DiskPoolZoneInfo]
    :param next_link: URI to fetch the next section of the paginated response.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[DiskPoolZoneInfo]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(DiskPoolZoneListResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = kwargs.get('next_link', None)


class EndpointDependency(msrest.serialization.Model):
    """A domain name that a service is reached at, including details of the current connection status.

    :param domain_name: The domain name of the dependency.
    :type domain_name: str
    :param endpoint_details: The IP Addresses and Ports used when connecting to DomainName.
    :type endpoint_details: list[~storage_pool_management.models.EndpointDetail]
    """

    _attribute_map = {
        'domain_name': {'key': 'domainName', 'type': 'str'},
        'endpoint_details': {'key': 'endpointDetails', 'type': '[EndpointDetail]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(EndpointDependency, self).__init__(**kwargs)
        self.domain_name = kwargs.get('domain_name', None)
        self.endpoint_details = kwargs.get('endpoint_details', None)


class EndpointDetail(msrest.serialization.Model):
    """Current TCP connectivity information from the App Service Environment to a single endpoint.

    :param ip_address: An IP Address that Domain Name currently resolves to.
    :type ip_address: str
    :param port: The port an endpoint is connected to.
    :type port: int
    :param latency: The time in milliseconds it takes for a TCP connection to be created from the
     App Service Environment to this IpAddress at this Port.
    :type latency: float
    :param is_accessible: Whether it is possible to create a TCP connection from the App Service
     Environment to this IpAddress at this Port.
    :type is_accessible: bool
    """

    _attribute_map = {
        'ip_address': {'key': 'ipAddress', 'type': 'str'},
        'port': {'key': 'port', 'type': 'int'},
        'latency': {'key': 'latency', 'type': 'float'},
        'is_accessible': {'key': 'isAccessible', 'type': 'bool'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(EndpointDetail, self).__init__(**kwargs)
        self.ip_address = kwargs.get('ip_address', None)
        self.port = kwargs.get('port', None)
        self.latency = kwargs.get('latency', None)
        self.is_accessible = kwargs.get('is_accessible', None)


class Error(msrest.serialization.Model):
    """The resource management error response.

    :param error: RP error response.
    :type error: ~storage_pool_management.models.ErrorResponse
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorResponse'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Error, self).__init__(**kwargs)
        self.error = kwargs.get('error', None)


class ErrorAdditionalInfo(msrest.serialization.Model):
    """The resource management error additional info.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar type: The additional info type.
    :vartype type: str
    :ivar info: The additional info.
    :vartype info: object
    """

    _validation = {
        'type': {'readonly': True},
        'info': {'readonly': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'info': {'key': 'info', 'type': 'object'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorAdditionalInfo, self).__init__(**kwargs)
        self.type = None
        self.info = None


class ErrorResponse(msrest.serialization.Model):
    """The resource management error response.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar code: The error code.
    :vartype code: str
    :ivar message: The error message.
    :vartype message: str
    :ivar target: The error target.
    :vartype target: str
    :ivar details: The error details.
    :vartype details: list[~storage_pool_management.models.ErrorResponse]
    :ivar additional_info: The error additional info.
    :vartype additional_info: list[~storage_pool_management.models.ErrorAdditionalInfo]
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
        'target': {'readonly': True},
        'details': {'readonly': True},
        'additional_info': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ErrorResponse]'},
        'additional_info': {'key': 'additionalInfo', 'type': '[ErrorAdditionalInfo]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorResponse, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.target = None
        self.details = None
        self.additional_info = None


class IscsiLun(msrest.serialization.Model):
    """LUN to expose the Azure Managed Disk.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. User defined name for iSCSI LUN; example: "lun0".
    :type name: str
    :param managed_disk_azure_resource_id: Required. Azure Resource ID of the Managed Disk.
    :type managed_disk_azure_resource_id: str
    """

    _validation = {
        'name': {'required': True},
        'managed_disk_azure_resource_id': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'managed_disk_azure_resource_id': {'key': 'managedDiskAzureResourceId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(IscsiLun, self).__init__(**kwargs)
        self.name = kwargs['name']
        self.managed_disk_azure_resource_id = kwargs['managed_disk_azure_resource_id']


class IscsiTarget(Resource):
    """Response for iSCSI Target requests.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Ex- Microsoft.Compute/virtualMachines or
     Microsoft.Storage/storageAccounts.
    :vartype type: str
    :ivar system_data: Resource metadata required by ARM RPC.
    :vartype system_data: ~storage_pool_management.models.SystemMetadata
    :param acl_mode: Required. Mode for Target connectivity. Possible values include: "Dynamic",
     "Static".
    :type acl_mode: str or ~storage_pool_management.models.IscsiTargetAclMode
    :param static_acls: Access Control List (ACL) for an iSCSI Target; defines LUN masking policy.
    :type static_acls: list[~storage_pool_management.models.Acl]
    :param luns: List of LUNs to be exposed through iSCSI Target.
    :type luns: list[~storage_pool_management.models.IscsiLun]
    :param target_iqn: Required. iSCSI Target IQN (iSCSI Qualified Name); example:
     "iqn.2005-03.org.iscsi:server".
    :type target_iqn: str
    :ivar provisioning_state: Required. State of the operation on the resource. Possible values
     include: "Invalid", "Succeeded", "Failed", "Canceled", "Pending", "Creating", "Updating",
     "Deleting".
    :vartype provisioning_state: str or ~storage_pool_management.models.ProvisioningStates
    :param status: Required. Operational status of the iSCSI Target. Possible values include:
     "Invalid", "Unknown", "Healthy", "Unhealthy", "Updating", "Running", "Stopped", "Stopped
     (deallocated)".
    :type status: str or ~storage_pool_management.models.OperationalStatus
    :param endpoints: List of private IPv4 addresses to connect to the iSCSI Target.
    :type endpoints: list[str]
    :param port: The port used by iSCSI Target portal group.
    :type port: int
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'system_data': {'readonly': True},
        'acl_mode': {'required': True},
        'target_iqn': {'required': True},
        'provisioning_state': {'required': True, 'readonly': True},
        'status': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'system_data': {'key': 'systemData', 'type': 'SystemMetadata'},
        'acl_mode': {'key': 'properties.aclMode', 'type': 'str'},
        'static_acls': {'key': 'properties.staticAcls', 'type': '[Acl]'},
        'luns': {'key': 'properties.luns', 'type': '[IscsiLun]'},
        'target_iqn': {'key': 'properties.targetIqn', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'endpoints': {'key': 'properties.endpoints', 'type': '[str]'},
        'port': {'key': 'properties.port', 'type': 'int'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(IscsiTarget, self).__init__(**kwargs)
        self.system_data = None
        self.acl_mode = kwargs['acl_mode']
        self.static_acls = kwargs.get('static_acls', None)
        self.luns = kwargs.get('luns', None)
        self.target_iqn = kwargs['target_iqn']
        self.provisioning_state = None
        self.status = kwargs['status']
        self.endpoints = kwargs.get('endpoints', None)
        self.port = kwargs.get('port', None)


class IscsiTargetCreate(Resource):
    """Payload for iSCSI Target create or update requests.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Ex- Microsoft.Compute/virtualMachines or
     Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param acl_mode: Required. Mode for Target connectivity. Possible values include: "Dynamic",
     "Static".
    :type acl_mode: str or ~storage_pool_management.models.IscsiTargetAclMode
    :param target_iqn: iSCSI Target IQN (iSCSI Qualified Name); example:
     "iqn.2005-03.org.iscsi:server".
    :type target_iqn: str
    :param static_acls: Access Control List (ACL) for an iSCSI Target; defines LUN masking policy.
    :type static_acls: list[~storage_pool_management.models.Acl]
    :param luns: List of LUNs to be exposed through iSCSI Target.
    :type luns: list[~storage_pool_management.models.IscsiLun]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'acl_mode': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'acl_mode': {'key': 'properties.aclMode', 'type': 'str'},
        'target_iqn': {'key': 'properties.targetIqn', 'type': 'str'},
        'static_acls': {'key': 'properties.staticAcls', 'type': '[Acl]'},
        'luns': {'key': 'properties.luns', 'type': '[IscsiLun]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(IscsiTargetCreate, self).__init__(**kwargs)
        self.acl_mode = kwargs['acl_mode']
        self.target_iqn = kwargs.get('target_iqn', None)
        self.static_acls = kwargs.get('static_acls', None)
        self.luns = kwargs.get('luns', None)


class IscsiTargetList(msrest.serialization.Model):
    """List of iSCSI Targets.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. An array of iSCSI Targets in a Disk Pool.
    :type value: list[~storage_pool_management.models.IscsiTarget]
    :ivar next_link: URI to fetch the next section of the paginated response.
    :vartype next_link: str
    """

    _validation = {
        'value': {'required': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[IscsiTarget]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(IscsiTargetList, self).__init__(**kwargs)
        self.value = kwargs['value']
        self.next_link = None


class IscsiTargetUpdate(Resource):
    """Payload for iSCSI Target update requests.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Ex- Microsoft.Compute/virtualMachines or
     Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param static_acls: Access Control List (ACL) for an iSCSI Target; defines LUN masking policy.
    :type static_acls: list[~storage_pool_management.models.Acl]
    :param luns: List of LUNs to be exposed through iSCSI Target.
    :type luns: list[~storage_pool_management.models.IscsiLun]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'static_acls': {'key': 'properties.staticAcls', 'type': '[Acl]'},
        'luns': {'key': 'properties.luns', 'type': '[IscsiLun]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(IscsiTargetUpdate, self).__init__(**kwargs)
        self.static_acls = kwargs.get('static_acls', None)
        self.luns = kwargs.get('luns', None)


class OutboundEnvironmentEndpoint(msrest.serialization.Model):
    """Endpoints accessed for a common purpose that the App Service Environment requires outbound network access to.

    :param category: The type of service accessed by the App Service Environment, e.g., Azure
     Storage, Azure SQL Database, and Azure Active Directory.
    :type category: str
    :param endpoints: The endpoints that the App Service Environment reaches the service at.
    :type endpoints: list[~storage_pool_management.models.EndpointDependency]
    """

    _attribute_map = {
        'category': {'key': 'category', 'type': 'str'},
        'endpoints': {'key': 'endpoints', 'type': '[EndpointDependency]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OutboundEnvironmentEndpoint, self).__init__(**kwargs)
        self.category = kwargs.get('category', None)
        self.endpoints = kwargs.get('endpoints', None)


class OutboundEnvironmentEndpointList(msrest.serialization.Model):
    """Collection of Outbound Environment Endpoints.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. Collection of resources.
    :type value: list[~storage_pool_management.models.OutboundEnvironmentEndpoint]
    :ivar next_link: Link to next page of resources.
    :vartype next_link: str
    """

    _validation = {
        'value': {'required': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[OutboundEnvironmentEndpoint]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(OutboundEnvironmentEndpointList, self).__init__(**kwargs)
        self.value = kwargs['value']
        self.next_link = None


class ProxyResource(Resource):
    """The resource model definition for a ARM proxy resource. It will have everything other than required location and tags.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Ex- Microsoft.Compute/virtualMachines or
     Microsoft.Storage/storageAccounts.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ProxyResource, self).__init__(**kwargs)


class Sku(msrest.serialization.Model):
    """Sku for ARM resource.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Sku name.
    :type name: str
    :param tier: Sku tier.
    :type tier: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Sku, self).__init__(**kwargs)
        self.name = kwargs['name']
        self.tier = kwargs.get('tier', None)


class StoragePoolOperationDisplay(msrest.serialization.Model):
    """Metadata about an operation.

    All required parameters must be populated in order to send to Azure.

    :param provider: Required. Localized friendly form of the resource provider name.
    :type provider: str
    :param resource: Required. Localized friendly form of the resource type related to this
     action/operation.
    :type resource: str
    :param operation: Required. Localized friendly name for the operation, as it should be shown to
     the user.
    :type operation: str
    :param description: Required. Localized friendly description for the operation, as it should be
     shown to the user.
    :type description: str
    """

    _validation = {
        'provider': {'required': True},
        'resource': {'required': True},
        'operation': {'required': True},
        'description': {'required': True},
    }

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(StoragePoolOperationDisplay, self).__init__(**kwargs)
        self.provider = kwargs['provider']
        self.resource = kwargs['resource']
        self.operation = kwargs['operation']
        self.description = kwargs['description']


class StoragePoolOperationListResult(msrest.serialization.Model):
    """List of operations supported by the RP.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. An array of operations supported by the StoragePool RP.
    :type value: list[~storage_pool_management.models.StoragePoolRpOperation]
    :param next_link: URI to fetch the next section of the paginated response.
    :type next_link: str
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[StoragePoolRpOperation]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(StoragePoolOperationListResult, self).__init__(**kwargs)
        self.value = kwargs['value']
        self.next_link = kwargs.get('next_link', None)


class StoragePoolRpOperation(msrest.serialization.Model):
    """Description of a StoragePool RP Operation.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the operation being performed on this particular object.
    :type name: str
    :param is_data_action: Required. Indicates whether the operation applies to data-plane.
    :type is_data_action: bool
    :param action_type: Indicates the action type.
    :type action_type: str
    :param display: Required. Additional metadata about RP operation.
    :type display: ~storage_pool_management.models.StoragePoolOperationDisplay
    :param origin: The intended executor of the operation; governs the display of the operation in
     the RBAC UX and the audit logs UX.
    :type origin: str
    """

    _validation = {
        'name': {'required': True},
        'is_data_action': {'required': True},
        'display': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'is_data_action': {'key': 'isDataAction', 'type': 'bool'},
        'action_type': {'key': 'actionType', 'type': 'str'},
        'display': {'key': 'display', 'type': 'StoragePoolOperationDisplay'},
        'origin': {'key': 'origin', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(StoragePoolRpOperation, self).__init__(**kwargs)
        self.name = kwargs['name']
        self.is_data_action = kwargs['is_data_action']
        self.action_type = kwargs.get('action_type', None)
        self.display = kwargs['display']
        self.origin = kwargs.get('origin', None)


class SystemMetadata(msrest.serialization.Model):
    """Metadata pertaining to creation and last modification of the resource.

    :param created_by: The identity that created the resource.
    :type created_by: str
    :param created_by_type: The type of identity that created the resource. Possible values
     include: "User", "Application", "ManagedIdentity", "Key".
    :type created_by_type: str or ~storage_pool_management.models.CreatedByType
    :param created_at: The timestamp of resource creation (UTC).
    :type created_at: ~datetime.datetime
    :param last_modified_by: The identity that last modified the resource.
    :type last_modified_by: str
    :param last_modified_by_type: The type of identity that last modified the resource. Possible
     values include: "User", "Application", "ManagedIdentity", "Key".
    :type last_modified_by_type: str or ~storage_pool_management.models.CreatedByType
    :param last_modified_at: The type of identity that last modified the resource.
    :type last_modified_at: ~datetime.datetime
    """

    _attribute_map = {
        'created_by': {'key': 'createdBy', 'type': 'str'},
        'created_by_type': {'key': 'createdByType', 'type': 'str'},
        'created_at': {'key': 'createdAt', 'type': 'iso-8601'},
        'last_modified_by': {'key': 'lastModifiedBy', 'type': 'str'},
        'last_modified_by_type': {'key': 'lastModifiedByType', 'type': 'str'},
        'last_modified_at': {'key': 'lastModifiedAt', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SystemMetadata, self).__init__(**kwargs)
        self.created_by = kwargs.get('created_by', None)
        self.created_by_type = kwargs.get('created_by_type', None)
        self.created_at = kwargs.get('created_at', None)
        self.last_modified_by = kwargs.get('last_modified_by', None)
        self.last_modified_by_type = kwargs.get('last_modified_by_type', None)
        self.last_modified_at = kwargs.get('last_modified_at', None)
