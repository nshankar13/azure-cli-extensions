# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
#
# Code generated by aaz-dev-tools
# --------------------------------------------------------------------------------------------

# pylint: skip-file
# flake8: noqa

from azure.cli.core.aaz import *


class Update(AAZCommand):
    """Update dhcp by id in a private cloud workload network.
    """

    _aaz_info = {
        "version": "2023-03-01",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.avs/privateclouds/{}/workloadnetworks/default/dhcpconfigurations/{}", "2023-03-01"],
        ]
    }

    AZ_SUPPORT_NO_WAIT = True

    AZ_SUPPORT_GENERIC_UPDATE = True

    def _handler(self, command_args):
        super()._handler(command_args)
        return self.build_lro_poller(self._execute_operations, self._output)

    _args_schema = None

    @classmethod
    def _build_arguments_schema(cls, *args, **kwargs):
        if cls._args_schema is not None:
            return cls._args_schema
        cls._args_schema = super()._build_arguments_schema(*args, **kwargs)

        # define Arg Group ""

        _args_schema = cls._args_schema
        _args_schema.dhcp = AAZStrArg(
            options=["-n", "--dhcp", "--name"],
            help="NSX DHCP identifier. Generally the same as the DHCP display name",
            required=True,
            id_part="child_name_2",
        )
        _args_schema.private_cloud = AAZStrArg(
            options=["-c", "--private-cloud"],
            help="Name of the private cloud",
            required=True,
            id_part="name",
            fmt=AAZStrArgFormat(
                pattern="^[-\w\._]+$",
            ),
        )
        _args_schema.resource_group = AAZResourceGroupNameArg(
            required=True,
        )

        # define Arg Group "Properties"

        _args_schema = cls._args_schema
        _args_schema.relay = AAZObjectArg(
            options=["--relay"],
            arg_group="Properties",
        )
        _args_schema.server = AAZObjectArg(
            options=["--server"],
            arg_group="Properties",
        )
        _args_schema.display_name = AAZStrArg(
            options=["--display-name"],
            arg_group="Properties",
            help="Display name of the DHCP entity.",
            nullable=True,
        )
        _args_schema.revision = AAZIntArg(
            options=["--revision"],
            arg_group="Properties",
            help="NSX revision number.",
            nullable=True,
        )

        relay = cls._args_schema.relay
        relay.server_addresses = AAZListArg(
            options=["server-addresses"],
            help="DHCP Relay Addresses. Max 3.",
            nullable=True,
        )

        server_addresses = cls._args_schema.relay.server_addresses
        server_addresses.Element = AAZStrArg(
            nullable=True,
        )

        server = cls._args_schema.server
        server.lease_time = AAZIntArg(
            options=["lease-time"],
            help="DHCP Server Lease Time.",
            nullable=True,
        )
        server.server_address = AAZStrArg(
            options=["server-address"],
            help="DHCP Server Address.",
            nullable=True,
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        self.WorkloadNetworksGetDhcp(ctx=self.ctx)()
        self.pre_instance_update(self.ctx.vars.instance)
        self.InstanceUpdateByJson(ctx=self.ctx)()
        self.InstanceUpdateByGeneric(ctx=self.ctx)()
        self.post_instance_update(self.ctx.vars.instance)
        yield self.WorkloadNetworksCreateDhcp(ctx=self.ctx)()
        self.post_operations()

    @register_callback
    def pre_operations(self):
        pass

    @register_callback
    def post_operations(self):
        pass

    @register_callback
    def pre_instance_update(self, instance):
        pass

    @register_callback
    def post_instance_update(self, instance):
        pass

    def _output(self, *args, **kwargs):
        result = self.deserialize_output(self.ctx.vars.instance, client_flatten=True)
        return result

    class WorkloadNetworksGetDhcp(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AVS/privateClouds/{privateCloudName}/workloadNetworks/default/dhcpConfigurations/{dhcpId}",
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
                    "dhcpId", self.ctx.args.dhcp,
                    required=True,
                ),
                **self.serialize_url_param(
                    "privateCloudName", self.ctx.args.private_cloud,
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
                    "api-version", "2023-03-01",
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
            _UpdateHelper._build_schema_workload_network_dhcp_read(cls._schema_on_200)

            return cls._schema_on_200

    class WorkloadNetworksCreateDhcp(AAZHttpOperation):
        CLIENT_TYPE = "MgmtClient"

        def __call__(self, *args, **kwargs):
            request = self.make_request()
            session = self.client.send_request(request=request, stream=False, **kwargs)
            if session.http_response.status_code in [202]:
                return self.client.build_lro_polling(
                    self.ctx.args.no_wait,
                    session,
                    self.on_200_201,
                    self.on_error,
                    lro_options={"final-state-via": "azure-async-operation"},
                    path_format_arguments=self.url_parameters,
                )
            if session.http_response.status_code in [200, 201]:
                return self.client.build_lro_polling(
                    self.ctx.args.no_wait,
                    session,
                    self.on_200_201,
                    self.on_error,
                    lro_options={"final-state-via": "azure-async-operation"},
                    path_format_arguments=self.url_parameters,
                )

            return self.on_error(session.http_response)

        @property
        def url(self):
            return self.client.format_url(
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AVS/privateClouds/{privateCloudName}/workloadNetworks/default/dhcpConfigurations/{dhcpId}",
                **self.url_parameters
            )

        @property
        def method(self):
            return "PUT"

        @property
        def error_format(self):
            return "MgmtErrorFormat"

        @property
        def url_parameters(self):
            parameters = {
                **self.serialize_url_param(
                    "dhcpId", self.ctx.args.dhcp,
                    required=True,
                ),
                **self.serialize_url_param(
                    "privateCloudName", self.ctx.args.private_cloud,
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
                    "api-version", "2023-03-01",
                    required=True,
                ),
            }
            return parameters

        @property
        def header_parameters(self):
            parameters = {
                **self.serialize_header_param(
                    "Content-Type", "application/json",
                ),
                **self.serialize_header_param(
                    "Accept", "application/json",
                ),
            }
            return parameters

        @property
        def content(self):
            _content_value, _builder = self.new_content_builder(
                self.ctx.args,
                value=self.ctx.vars.instance,
            )

            return self.serialize_content(_content_value)

        def on_200_201(self, session):
            data = self.deserialize_http_content(session)
            self.ctx.set_var(
                "instance",
                data,
                schema_builder=self._build_schema_on_200_201
            )

        _schema_on_200_201 = None

        @classmethod
        def _build_schema_on_200_201(cls):
            if cls._schema_on_200_201 is not None:
                return cls._schema_on_200_201

            cls._schema_on_200_201 = AAZObjectType()
            _UpdateHelper._build_schema_workload_network_dhcp_read(cls._schema_on_200_201)

            return cls._schema_on_200_201

    class InstanceUpdateByJson(AAZJsonInstanceUpdateOperation):

        def __call__(self, *args, **kwargs):
            self._update_instance(self.ctx.vars.instance)

        def _update_instance(self, instance):
            _instance_value, _builder = self.new_content_builder(
                self.ctx.args,
                value=instance,
                typ=AAZObjectType
            )
            _builder.set_prop("properties", AAZObjectType)

            properties = _builder.get(".properties")
            if properties is not None:
                properties.set_const("dhcpType", "RELAY", AAZStrType, ".relay", typ_kwargs={"flags": {"required": True}})
                properties.set_const("dhcpType", "SERVER", AAZStrType, ".server", typ_kwargs={"flags": {"required": True}})
                properties.set_prop("displayName", AAZStrType, ".display_name")
                properties.set_prop("revision", AAZIntType, ".revision")
                properties.discriminate_by("dhcpType", "RELAY")
                properties.discriminate_by("dhcpType", "SERVER")

            disc_relay = _builder.get(".properties{dhcpType:RELAY}")
            if disc_relay is not None:
                disc_relay.set_prop("serverAddresses", AAZListType, ".relay.server_addresses")

            server_addresses = _builder.get(".properties{dhcpType:RELAY}.serverAddresses")
            if server_addresses is not None:
                server_addresses.set_elements(AAZStrType, ".")

            disc_server = _builder.get(".properties{dhcpType:SERVER}")
            if disc_server is not None:
                disc_server.set_prop("leaseTime", AAZIntType, ".server.lease_time")
                disc_server.set_prop("serverAddress", AAZStrType, ".server.server_address")

            return _instance_value

    class InstanceUpdateByGeneric(AAZGenericInstanceUpdateOperation):

        def __call__(self, *args, **kwargs):
            self._update_instance_by_generic(
                self.ctx.vars.instance,
                self.ctx.generic_update_args
            )


class _UpdateHelper:
    """Helper class for Update"""

    _schema_workload_network_dhcp_read = None

    @classmethod
    def _build_schema_workload_network_dhcp_read(cls, _schema):
        if cls._schema_workload_network_dhcp_read is not None:
            _schema.id = cls._schema_workload_network_dhcp_read.id
            _schema.name = cls._schema_workload_network_dhcp_read.name
            _schema.properties = cls._schema_workload_network_dhcp_read.properties
            _schema.type = cls._schema_workload_network_dhcp_read.type
            return

        cls._schema_workload_network_dhcp_read = _schema_workload_network_dhcp_read = AAZObjectType()

        workload_network_dhcp_read = _schema_workload_network_dhcp_read
        workload_network_dhcp_read.id = AAZStrType(
            flags={"read_only": True},
        )
        workload_network_dhcp_read.name = AAZStrType(
            flags={"read_only": True},
        )
        workload_network_dhcp_read.properties = AAZObjectType()
        workload_network_dhcp_read.type = AAZStrType(
            flags={"read_only": True},
        )

        properties = _schema_workload_network_dhcp_read.properties
        properties.dhcp_type = AAZStrType(
            serialized_name="dhcpType",
            flags={"required": True},
        )
        properties.display_name = AAZStrType(
            serialized_name="displayName",
        )
        properties.provisioning_state = AAZStrType(
            serialized_name="provisioningState",
            flags={"read_only": True},
        )
        properties.revision = AAZIntType()
        properties.segments = AAZListType(
            flags={"read_only": True},
        )

        segments = _schema_workload_network_dhcp_read.properties.segments
        segments.Element = AAZStrType()

        disc_relay = _schema_workload_network_dhcp_read.properties.discriminate_by("dhcp_type", "RELAY")
        disc_relay.server_addresses = AAZListType(
            serialized_name="serverAddresses",
        )

        server_addresses = _schema_workload_network_dhcp_read.properties.discriminate_by("dhcp_type", "RELAY").server_addresses
        server_addresses.Element = AAZStrType()

        disc_server = _schema_workload_network_dhcp_read.properties.discriminate_by("dhcp_type", "SERVER")
        disc_server.lease_time = AAZIntType(
            serialized_name="leaseTime",
        )
        disc_server.server_address = AAZStrType(
            serialized_name="serverAddress",
        )

        _schema.id = cls._schema_workload_network_dhcp_read.id
        _schema.name = cls._schema_workload_network_dhcp_read.name
        _schema.properties = cls._schema_workload_network_dhcp_read.properties
        _schema.type = cls._schema_workload_network_dhcp_read.type


__all__ = ["Update"]
