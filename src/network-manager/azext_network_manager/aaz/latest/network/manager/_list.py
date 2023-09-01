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
    "network manager list",
)
class List(AAZCommand):
    """List all network managers in a subscription.

    :example: List Azure Virtual Network Manager
        az network manager list --resource-group "rg1"
    """

    _aaz_info = {
        "version": "2022-01-01",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/providers/microsoft.network/networkmanagers", "2022-01-01"],
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.network/networkmanagers", "2022-01-01"],
        ]
    }

    AZ_SUPPORT_PAGINATION = True

    def _handler(self, command_args):
        super()._handler(command_args)
        return self.build_paging(self._execute_operations, self._output)

    _args_schema = None

    @classmethod
    def _build_arguments_schema(cls, *args, **kwargs):
        if cls._args_schema is not None:
            return cls._args_schema
        cls._args_schema = super()._build_arguments_schema(*args, **kwargs)

        # define Arg Group ""

        _args_schema = cls._args_schema
        _args_schema.resource_group = AAZResourceGroupNameArg()
        _args_schema.skip_token = AAZStrArg(
            options=["--skip-token"],
            help="SkipToken is only used if a previous operation returned a partial result. If a previous response contains a nextLink element, the value of the nextLink element will include a skipToken parameter that specifies a starting point to use for subsequent calls.",
        )
        _args_schema.top = AAZIntArg(
            options=["--top"],
            help="An optional query parameter which specifies the maximum number of records to be returned by the server.",
            fmt=AAZIntArgFormat(
                maximum=20,
                minimum=1,
            ),
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        condition_0 = has_value(self.ctx.args.resource_group) and has_value(self.ctx.subscription_id)
        condition_1 = has_value(self.ctx.subscription_id) and has_value(self.ctx.args.resource_group) is not True
        if condition_0:
            self.NetworkManagersList(ctx=self.ctx)()
        if condition_1:
            self.NetworkManagersListBySubscription(ctx=self.ctx)()
        self.post_operations()

    @register_callback
    def pre_operations(self):
        pass

    @register_callback
    def post_operations(self):
        pass

    def _output(self, *args, **kwargs):
        result = self.deserialize_output(self.ctx.vars.instance.value, client_flatten=True)
        next_link = self.deserialize_output(self.ctx.vars.instance.next_link)
        return result, next_link

    class NetworkManagersList(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkManagers",
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
                    "$skipToken", self.ctx.args.skip_token,
                ),
                **self.serialize_query_param(
                    "$top", self.ctx.args.top,
                ),
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

            _schema_on_200 = cls._schema_on_200
            _schema_on_200.next_link = AAZStrType(
                serialized_name="nextLink",
            )
            _schema_on_200.value = AAZListType()

            value = cls._schema_on_200.value
            value.Element = AAZObjectType()

            _element = cls._schema_on_200.value.Element
            _element.etag = AAZStrType(
                flags={"read_only": True},
            )
            _element.id = AAZStrType()
            _element.location = AAZStrType()
            _element.name = AAZStrType(
                flags={"read_only": True},
            )
            _element.properties = AAZObjectType(
                flags={"client_flatten": True},
            )
            _element.system_data = AAZObjectType(
                serialized_name="systemData",
                flags={"read_only": True},
            )
            _element.tags = AAZDictType()
            _element.type = AAZStrType(
                flags={"read_only": True},
            )

            properties = cls._schema_on_200.value.Element.properties
            properties.description = AAZStrType()
            properties.network_manager_scope_accesses = AAZListType(
                serialized_name="networkManagerScopeAccesses",
                flags={"required": True},
            )
            properties.network_manager_scopes = AAZObjectType(
                serialized_name="networkManagerScopes",
                flags={"required": True},
            )
            properties.provisioning_state = AAZStrType(
                serialized_name="provisioningState",
                flags={"read_only": True},
            )

            network_manager_scope_accesses = cls._schema_on_200.value.Element.properties.network_manager_scope_accesses
            network_manager_scope_accesses.Element = AAZStrType()

            network_manager_scopes = cls._schema_on_200.value.Element.properties.network_manager_scopes
            network_manager_scopes.cross_tenant_scopes = AAZListType(
                serialized_name="crossTenantScopes",
                flags={"read_only": True},
            )
            network_manager_scopes.management_groups = AAZListType(
                serialized_name="managementGroups",
            )
            network_manager_scopes.subscriptions = AAZListType()

            cross_tenant_scopes = cls._schema_on_200.value.Element.properties.network_manager_scopes.cross_tenant_scopes
            cross_tenant_scopes.Element = AAZObjectType()

            _element = cls._schema_on_200.value.Element.properties.network_manager_scopes.cross_tenant_scopes.Element
            _element.management_groups = AAZListType(
                serialized_name="managementGroups",
                flags={"read_only": True},
            )
            _element.subscriptions = AAZListType(
                flags={"read_only": True},
            )
            _element.tenant_id = AAZStrType(
                serialized_name="tenantId",
                flags={"read_only": True},
            )

            management_groups = cls._schema_on_200.value.Element.properties.network_manager_scopes.cross_tenant_scopes.Element.management_groups
            management_groups.Element = AAZStrType()

            subscriptions = cls._schema_on_200.value.Element.properties.network_manager_scopes.cross_tenant_scopes.Element.subscriptions
            subscriptions.Element = AAZStrType()

            management_groups = cls._schema_on_200.value.Element.properties.network_manager_scopes.management_groups
            management_groups.Element = AAZStrType()

            subscriptions = cls._schema_on_200.value.Element.properties.network_manager_scopes.subscriptions
            subscriptions.Element = AAZStrType()

            system_data = cls._schema_on_200.value.Element.system_data
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

            tags = cls._schema_on_200.value.Element.tags
            tags.Element = AAZStrType()

            return cls._schema_on_200

    class NetworkManagersListBySubscription(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkManagers",
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
                    "subscriptionId", self.ctx.subscription_id,
                    required=True,
                ),
            }
            return parameters

        @property
        def query_parameters(self):
            parameters = {
                **self.serialize_query_param(
                    "$skipToken", self.ctx.args.skip_token,
                ),
                **self.serialize_query_param(
                    "$top", self.ctx.args.top,
                ),
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

            _schema_on_200 = cls._schema_on_200
            _schema_on_200.next_link = AAZStrType(
                serialized_name="nextLink",
            )
            _schema_on_200.value = AAZListType()

            value = cls._schema_on_200.value
            value.Element = AAZObjectType()

            _element = cls._schema_on_200.value.Element
            _element.etag = AAZStrType(
                flags={"read_only": True},
            )
            _element.id = AAZStrType()
            _element.location = AAZStrType()
            _element.name = AAZStrType(
                flags={"read_only": True},
            )
            _element.properties = AAZObjectType(
                flags={"client_flatten": True},
            )
            _element.system_data = AAZObjectType(
                serialized_name="systemData",
                flags={"read_only": True},
            )
            _element.tags = AAZDictType()
            _element.type = AAZStrType(
                flags={"read_only": True},
            )

            properties = cls._schema_on_200.value.Element.properties
            properties.description = AAZStrType()
            properties.network_manager_scope_accesses = AAZListType(
                serialized_name="networkManagerScopeAccesses",
                flags={"required": True},
            )
            properties.network_manager_scopes = AAZObjectType(
                serialized_name="networkManagerScopes",
                flags={"required": True},
            )
            properties.provisioning_state = AAZStrType(
                serialized_name="provisioningState",
                flags={"read_only": True},
            )

            network_manager_scope_accesses = cls._schema_on_200.value.Element.properties.network_manager_scope_accesses
            network_manager_scope_accesses.Element = AAZStrType()

            network_manager_scopes = cls._schema_on_200.value.Element.properties.network_manager_scopes
            network_manager_scopes.cross_tenant_scopes = AAZListType(
                serialized_name="crossTenantScopes",
                flags={"read_only": True},
            )
            network_manager_scopes.management_groups = AAZListType(
                serialized_name="managementGroups",
            )
            network_manager_scopes.subscriptions = AAZListType()

            cross_tenant_scopes = cls._schema_on_200.value.Element.properties.network_manager_scopes.cross_tenant_scopes
            cross_tenant_scopes.Element = AAZObjectType()

            _element = cls._schema_on_200.value.Element.properties.network_manager_scopes.cross_tenant_scopes.Element
            _element.management_groups = AAZListType(
                serialized_name="managementGroups",
                flags={"read_only": True},
            )
            _element.subscriptions = AAZListType(
                flags={"read_only": True},
            )
            _element.tenant_id = AAZStrType(
                serialized_name="tenantId",
                flags={"read_only": True},
            )

            management_groups = cls._schema_on_200.value.Element.properties.network_manager_scopes.cross_tenant_scopes.Element.management_groups
            management_groups.Element = AAZStrType()

            subscriptions = cls._schema_on_200.value.Element.properties.network_manager_scopes.cross_tenant_scopes.Element.subscriptions
            subscriptions.Element = AAZStrType()

            management_groups = cls._schema_on_200.value.Element.properties.network_manager_scopes.management_groups
            management_groups.Element = AAZStrType()

            subscriptions = cls._schema_on_200.value.Element.properties.network_manager_scopes.subscriptions
            subscriptions.Element = AAZStrType()

            system_data = cls._schema_on_200.value.Element.system_data
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

            tags = cls._schema_on_200.value.Element.tags
            tags.Element = AAZStrType()

            return cls._schema_on_200


class _ListHelper:
    """Helper class for List"""


__all__ = ["List"]
