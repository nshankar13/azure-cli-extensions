# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
#
# Code generated by aaz-dev-tools
# --------------------------------------------------------------------------------------------

# pylint: skip-file
# flake8: noqa

from azure.cli.core.aaz import *


@register_command(
    "networkcloud baremetalmachine wait",
)
class Wait(AAZWaitCommand):
    """Place the CLI in a waiting state until a condition is met.
    """

    _aaz_info = {
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.networkcloud/baremetalmachines/{}", "2023-10-01-preview"],
        ]
    }

    def _handler(self, command_args):
        super()._handler(command_args)
        self._execute_operations()
        return self._output()

    _args_schema = None

    @classmethod
    def _build_arguments_schema(cls, *args, **kwargs):
        if cls._args_schema is not None:
            return cls._args_schema
        cls._args_schema = super()._build_arguments_schema(*args, **kwargs)

        # define Arg Group ""

        _args_schema = cls._args_schema
        _args_schema.bare_metal_machine_name = AAZStrArg(
            options=["-n", "--name", "--bare-metal-machine-name"],
            help="The name of the bare metal machine.",
            required=True,
            id_part="name",
            fmt=AAZStrArgFormat(
                pattern="^([a-zA-Z0-9][a-zA-Z0-9]{0,62}[a-zA-Z0-9])$",
            ),
        )
        _args_schema.resource_group = AAZResourceGroupNameArg(
            required=True,
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        self.BareMetalMachinesGet(ctx=self.ctx)()
        self.post_operations()

    @register_callback
    def pre_operations(self):
        pass

    @register_callback
    def post_operations(self):
        pass

    def _output(self, *args, **kwargs):
        result = self.deserialize_output(self.ctx.vars.instance, client_flatten=False)
        return result

    class BareMetalMachinesGet(AAZHttpOperation):
        CLIENT_TYPE = "MgmtClient"

        def __call__(self, *args, **kwargs):
            request = self.make_request()
            session = self.client.send_request(request=request, stream=False, **kwargs)
            if session.http_response.status_code in [200]:
                return self.on_200(session)

            return self.on_error(session.http_response)

        @property
        def url(self):
            return self.client.format_url(
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetworkCloud/bareMetalMachines/{bareMetalMachineName}",
                **self.url_parameters
            )

        @property
        def method(self):
            return "GET"

        @property
        def error_format(self):
            return "MgmtErrorFormat"

        @property
        def url_parameters(self):
            parameters = {
                **self.serialize_url_param(
                    "bareMetalMachineName", self.ctx.args.bare_metal_machine_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "resourceGroupName", self.ctx.args.resource_group,
                    required=True,
                ),
                **self.serialize_url_param(
                    "subscriptionId", self.ctx.subscription_id,
                    required=True,
                ),
            }
            return parameters

        @property
        def query_parameters(self):
            parameters = {
                **self.serialize_query_param(
                    "api-version", "2023-10-01-preview",
                    required=True,
                ),
            }
            return parameters

        @property
        def header_parameters(self):
            parameters = {
                **self.serialize_header_param(
                    "Accept", "application/json",
                ),
            }
            return parameters

        def on_200(self, session):
            data = self.deserialize_http_content(session)
            self.ctx.set_var(
                "instance",
                data,
                schema_builder=self._build_schema_on_200
            )

        _schema_on_200 = None

        @classmethod
        def _build_schema_on_200(cls):
            if cls._schema_on_200 is not None:
                return cls._schema_on_200

            cls._schema_on_200 = AAZObjectType()

            _schema_on_200 = cls._schema_on_200
            _schema_on_200.extended_location = AAZObjectType(
                serialized_name="extendedLocation",
                flags={"required": True},
            )
            _schema_on_200.id = AAZStrType(
                flags={"read_only": True},
            )
            _schema_on_200.location = AAZStrType(
                flags={"required": True},
            )
            _schema_on_200.name = AAZStrType(
                flags={"read_only": True},
            )
            _schema_on_200.properties = AAZObjectType(
                flags={"required": True, "client_flatten": True},
            )
            _schema_on_200.system_data = AAZObjectType(
                serialized_name="systemData",
                flags={"read_only": True},
            )
            _schema_on_200.tags = AAZDictType()
            _schema_on_200.type = AAZStrType(
                flags={"read_only": True},
            )

            extended_location = cls._schema_on_200.extended_location
            extended_location.name = AAZStrType(
                flags={"required": True},
            )
            extended_location.type = AAZStrType(
                flags={"required": True},
            )

            properties = cls._schema_on_200.properties
            properties.associated_resource_ids = AAZListType(
                serialized_name="associatedResourceIds",
                flags={"read_only": True},
            )
            properties.bmc_connection_string = AAZStrType(
                serialized_name="bmcConnectionString",
                flags={"required": True},
            )
            properties.bmc_credentials = AAZObjectType(
                serialized_name="bmcCredentials",
                flags={"required": True},
            )
            properties.bmc_mac_address = AAZStrType(
                serialized_name="bmcMacAddress",
                flags={"required": True},
            )
            properties.boot_mac_address = AAZStrType(
                serialized_name="bootMacAddress",
                flags={"required": True},
            )
            properties.cluster_id = AAZStrType(
                serialized_name="clusterId",
                flags={"read_only": True},
            )
            properties.cordon_status = AAZStrType(
                serialized_name="cordonStatus",
                flags={"read_only": True},
            )
            properties.detailed_status = AAZStrType(
                serialized_name="detailedStatus",
                flags={"read_only": True},
            )
            properties.detailed_status_message = AAZStrType(
                serialized_name="detailedStatusMessage",
                flags={"read_only": True},
            )
            properties.hardware_inventory = AAZObjectType(
                serialized_name="hardwareInventory",
            )
            properties.hardware_validation_status = AAZObjectType(
                serialized_name="hardwareValidationStatus",
            )
            properties.hybrid_aks_clusters_associated_ids = AAZListType(
                serialized_name="hybridAksClustersAssociatedIds",
                flags={"read_only": True},
            )
            properties.kubernetes_node_name = AAZStrType(
                serialized_name="kubernetesNodeName",
                flags={"read_only": True},
            )
            properties.kubernetes_version = AAZStrType(
                serialized_name="kubernetesVersion",
                flags={"read_only": True},
            )
            properties.machine_details = AAZStrType(
                serialized_name="machineDetails",
                flags={"required": True},
            )
            properties.machine_name = AAZStrType(
                serialized_name="machineName",
                flags={"required": True},
            )
            properties.machine_roles = AAZListType(
                serialized_name="machineRoles",
                flags={"read_only": True},
            )
            properties.machine_sku_id = AAZStrType(
                serialized_name="machineSkuId",
                flags={"required": True},
            )
            properties.oam_ipv4_address = AAZStrType(
                serialized_name="oamIpv4Address",
                flags={"read_only": True},
            )
            properties.oam_ipv6_address = AAZStrType(
                serialized_name="oamIpv6Address",
                flags={"read_only": True},
            )
            properties.os_image = AAZStrType(
                serialized_name="osImage",
                flags={"read_only": True},
            )
            properties.power_state = AAZStrType(
                serialized_name="powerState",
                flags={"read_only": True},
            )
            properties.provisioning_state = AAZStrType(
                serialized_name="provisioningState",
                flags={"read_only": True},
            )
            properties.rack_id = AAZStrType(
                serialized_name="rackId",
                flags={"required": True},
            )
            properties.rack_slot = AAZIntType(
                serialized_name="rackSlot",
                flags={"required": True},
            )
            properties.ready_state = AAZStrType(
                serialized_name="readyState",
                flags={"read_only": True},
            )
            properties.runtime_protection_status = AAZObjectType(
                serialized_name="runtimeProtectionStatus",
            )
            properties.serial_number = AAZStrType(
                serialized_name="serialNumber",
                flags={"required": True},
            )
            properties.service_tag = AAZStrType(
                serialized_name="serviceTag",
                flags={"read_only": True},
            )
            properties.virtual_machines_associated_ids = AAZListType(
                serialized_name="virtualMachinesAssociatedIds",
                flags={"read_only": True},
            )

            associated_resource_ids = cls._schema_on_200.properties.associated_resource_ids
            associated_resource_ids.Element = AAZStrType()

            bmc_credentials = cls._schema_on_200.properties.bmc_credentials
            bmc_credentials.password = AAZStrType(
                flags={"secret": True},
            )
            bmc_credentials.username = AAZStrType(
                flags={"required": True},
            )

            hardware_inventory = cls._schema_on_200.properties.hardware_inventory
            hardware_inventory.additional_host_information = AAZStrType(
                serialized_name="additionalHostInformation",
                flags={"read_only": True},
            )
            hardware_inventory.interfaces = AAZListType(
                flags={"read_only": True},
            )
            hardware_inventory.nics = AAZListType(
                flags={"read_only": True},
            )

            interfaces = cls._schema_on_200.properties.hardware_inventory.interfaces
            interfaces.Element = AAZObjectType()

            _element = cls._schema_on_200.properties.hardware_inventory.interfaces.Element
            _element.link_status = AAZStrType(
                serialized_name="linkStatus",
                flags={"read_only": True},
            )
            _element.mac_address = AAZStrType(
                serialized_name="macAddress",
                flags={"read_only": True},
            )
            _element.name = AAZStrType(
                flags={"read_only": True},
            )
            _element.network_interface_id = AAZStrType(
                serialized_name="networkInterfaceId",
                flags={"read_only": True},
            )

            nics = cls._schema_on_200.properties.hardware_inventory.nics
            nics.Element = AAZObjectType()

            _element = cls._schema_on_200.properties.hardware_inventory.nics.Element
            _element.lldp_neighbor = AAZObjectType(
                serialized_name="lldpNeighbor",
            )
            _element.mac_address = AAZStrType(
                serialized_name="macAddress",
                flags={"read_only": True},
            )
            _element.name = AAZStrType(
                flags={"read_only": True},
            )

            lldp_neighbor = cls._schema_on_200.properties.hardware_inventory.nics.Element.lldp_neighbor
            lldp_neighbor.port_description = AAZStrType(
                serialized_name="portDescription",
                flags={"read_only": True},
            )
            lldp_neighbor.port_name = AAZStrType(
                serialized_name="portName",
                flags={"read_only": True},
            )
            lldp_neighbor.system_description = AAZStrType(
                serialized_name="systemDescription",
                flags={"read_only": True},
            )
            lldp_neighbor.system_name = AAZStrType(
                serialized_name="systemName",
                flags={"read_only": True},
            )

            hardware_validation_status = cls._schema_on_200.properties.hardware_validation_status
            hardware_validation_status.last_validation_time = AAZStrType(
                serialized_name="lastValidationTime",
                flags={"read_only": True},
            )
            hardware_validation_status.result = AAZStrType(
                flags={"read_only": True},
            )

            hybrid_aks_clusters_associated_ids = cls._schema_on_200.properties.hybrid_aks_clusters_associated_ids
            hybrid_aks_clusters_associated_ids.Element = AAZStrType()

            machine_roles = cls._schema_on_200.properties.machine_roles
            machine_roles.Element = AAZStrType()

            runtime_protection_status = cls._schema_on_200.properties.runtime_protection_status
            runtime_protection_status.definitions_last_updated = AAZStrType(
                serialized_name="definitionsLastUpdated",
                flags={"read_only": True},
            )
            runtime_protection_status.definitions_version = AAZStrType(
                serialized_name="definitionsVersion",
                flags={"read_only": True},
            )
            runtime_protection_status.scan_completed_time = AAZStrType(
                serialized_name="scanCompletedTime",
                flags={"read_only": True},
            )
            runtime_protection_status.scan_scheduled_time = AAZStrType(
                serialized_name="scanScheduledTime",
                flags={"read_only": True},
            )
            runtime_protection_status.scan_started_time = AAZStrType(
                serialized_name="scanStartedTime",
                flags={"read_only": True},
            )

            virtual_machines_associated_ids = cls._schema_on_200.properties.virtual_machines_associated_ids
            virtual_machines_associated_ids.Element = AAZStrType()

            system_data = cls._schema_on_200.system_data
            system_data.created_at = AAZStrType(
                serialized_name="createdAt",
            )
            system_data.created_by = AAZStrType(
                serialized_name="createdBy",
            )
            system_data.created_by_type = AAZStrType(
                serialized_name="createdByType",
            )
            system_data.last_modified_at = AAZStrType(
                serialized_name="lastModifiedAt",
            )
            system_data.last_modified_by = AAZStrType(
                serialized_name="lastModifiedBy",
            )
            system_data.last_modified_by_type = AAZStrType(
                serialized_name="lastModifiedByType",
            )

            tags = cls._schema_on_200.tags
            tags.Element = AAZStrType()

            return cls._schema_on_200


class _WaitHelper:
    """Helper class for Wait"""


__all__ = ["Wait"]
