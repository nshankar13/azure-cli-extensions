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
    "network manager connection management-group update",
)
class Update(AAZCommand):
    """Update a network manager connection on this management group.

    :example: Update network manager connection management-group
        az network manager connection management-group update --management-group-id "testManagementGroupId" --connection-name "testNetworkManagerConnection" --description "My Test Network Manager Connection"
    """

    _aaz_info = {
        "version": "2022-01-01",
        "resources": [
            ["mgmt-plane", "/providers/microsoft.management/managementgroups/{}/providers/microsoft.network/networkmanagerconnections/{}", "2022-01-01"],
        ]
    }

    AZ_SUPPORT_GENERIC_UPDATE = True

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
        _args_schema.management_group_id = AAZStrArg(
            options=["--management-group-id"],
            help="The management group Id which uniquely identify the Microsoft Azure management group.",
            required=True,
        )
        _args_schema.connection_name = AAZStrArg(
            options=["-n", "--name", "--connection-name"],
            help="Name for the network manager connection.",
            required=True,
        )

        # define Arg Group "Properties"

        _args_schema = cls._args_schema
        _args_schema.description = AAZStrArg(
            options=["--description"],
            arg_group="Properties",
            help="A description of the network manager connection.",
            nullable=True,
        )
        _args_schema.network_manager_id = AAZStrArg(
            options=["--network-manager", "--network-manager-id"],
            arg_group="Properties",
            help="Network Manager Id.",
            nullable=True,
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        self.ManagementGroupNetworkManagerConnectionsGet(ctx=self.ctx)()
        self.pre_instance_update(self.ctx.vars.instance)
        self.InstanceUpdateByJson(ctx=self.ctx)()
        self.InstanceUpdateByGeneric(ctx=self.ctx)()
        self.post_instance_update(self.ctx.vars.instance)
        self.ManagementGroupNetworkManagerConnectionsCreateOrUpdate(ctx=self.ctx)()
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

    class ManagementGroupNetworkManagerConnectionsGet(AAZHttpOperation):
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
                "/providers/Microsoft.Management/managementGroups/{managementGroupId}/providers/Microsoft.Network/networkManagerConnections/{networkManagerConnectionName}",
                **self.url_parameters
            )

        @property
        def method(self):
            return "GET"

        @property
        def error_format(self):
            return "ODataV4Format"

        @property
        def url_parameters(self):
            parameters = {
                **self.serialize_url_param(
                    "managementGroupId", self.ctx.args.management_group_id,
                    required=True,
                ),
                **self.serialize_url_param(
                    "networkManagerConnectionName", self.ctx.args.connection_name,
                    required=True,
                ),
            }
            return parameters

        @property
        def query_parameters(self):
            parameters = {
                **self.serialize_query_param(
                    "api-version", "2022-01-01",
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
            _UpdateHelper._build_schema_network_manager_connection_read(cls._schema_on_200)

            return cls._schema_on_200

    class ManagementGroupNetworkManagerConnectionsCreateOrUpdate(AAZHttpOperation):
        CLIENT_TYPE = "MgmtClient"

        def __call__(self, *args, **kwargs):
            request = self.make_request()
            session = self.client.send_request(request=request, stream=False, **kwargs)
            if session.http_response.status_code in [200, 201]:
                return self.on_200_201(session)

            return self.on_error(session.http_response)

        @property
        def url(self):
            return self.client.format_url(
                "/providers/Microsoft.Management/managementGroups/{managementGroupId}/providers/Microsoft.Network/networkManagerConnections/{networkManagerConnectionName}",
                **self.url_parameters
            )

        @property
        def method(self):
            return "PUT"

        @property
        def error_format(self):
            return "ODataV4Format"

        @property
        def url_parameters(self):
            parameters = {
                **self.serialize_url_param(
                    "managementGroupId", self.ctx.args.management_group_id,
                    required=True,
                ),
                **self.serialize_url_param(
                    "networkManagerConnectionName", self.ctx.args.connection_name,
                    required=True,
                ),
            }
            return parameters

        @property
        def query_parameters(self):
            parameters = {
                **self.serialize_query_param(
                    "api-version", "2022-01-01",
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
            _UpdateHelper._build_schema_network_manager_connection_read(cls._schema_on_200_201)

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
            _builder.set_prop("properties", AAZObjectType, typ_kwargs={"flags": {"client_flatten": True}})

            properties = _builder.get(".properties")
            if properties is not None:
                properties.set_prop("description", AAZStrType, ".description")
                properties.set_prop("networkManagerId", AAZStrType, ".network_manager_id")

            return _instance_value

    class InstanceUpdateByGeneric(AAZGenericInstanceUpdateOperation):

        def __call__(self, *args, **kwargs):
            self._update_instance_by_generic(
                self.ctx.vars.instance,
                self.ctx.generic_update_args
            )


class _UpdateHelper:
    """Helper class for Update"""

    _schema_network_manager_connection_read = None

    @classmethod
    def _build_schema_network_manager_connection_read(cls, _schema):
        if cls._schema_network_manager_connection_read is not None:
            _schema.etag = cls._schema_network_manager_connection_read.etag
            _schema.id = cls._schema_network_manager_connection_read.id
            _schema.name = cls._schema_network_manager_connection_read.name
            _schema.properties = cls._schema_network_manager_connection_read.properties
            _schema.system_data = cls._schema_network_manager_connection_read.system_data
            _schema.type = cls._schema_network_manager_connection_read.type
            return

        cls._schema_network_manager_connection_read = _schema_network_manager_connection_read = AAZObjectType()

        network_manager_connection_read = _schema_network_manager_connection_read
        network_manager_connection_read.etag = AAZStrType(
            flags={"read_only": True},
        )
        network_manager_connection_read.id = AAZStrType(
            flags={"read_only": True},
        )
        network_manager_connection_read.name = AAZStrType(
            flags={"read_only": True},
        )
        network_manager_connection_read.properties = AAZObjectType(
            flags={"client_flatten": True},
        )
        network_manager_connection_read.system_data = AAZObjectType(
            serialized_name="systemData",
            flags={"read_only": True},
        )
        network_manager_connection_read.type = AAZStrType(
            flags={"read_only": True},
        )

        properties = _schema_network_manager_connection_read.properties
        properties.connection_state = AAZStrType(
            serialized_name="connectionState",
            flags={"read_only": True},
        )
        properties.description = AAZStrType()
        properties.network_manager_id = AAZStrType(
            serialized_name="networkManagerId",
        )

        system_data = _schema_network_manager_connection_read.system_data
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

        _schema.etag = cls._schema_network_manager_connection_read.etag
        _schema.id = cls._schema_network_manager_connection_read.id
        _schema.name = cls._schema_network_manager_connection_read.name
        _schema.properties = cls._schema_network_manager_connection_read.properties
        _schema.system_data = cls._schema_network_manager_connection_read.system_data
        _schema.type = cls._schema_network_manager_connection_read.type


__all__ = ["Update"]
