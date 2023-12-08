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
    "logic workflow list",
)
class List(AAZCommand):
    """List a list of workflows by subscription.

    :example: List all workflows in a resource group
        az logic workflow list --resource-group rg

    :example: List all workflows in a subscription
        az logic workflow list
    """

    _aaz_info = {
        "version": "2019-05-01",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/providers/microsoft.logic/workflows", "2019-05-01"],
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.logic/workflows", "2019-05-01"],
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
        _args_schema.filter = AAZStrArg(
            options=["--filter"],
            help="The filter to apply on the operation. Options for filters include: State, Trigger, and ReferencedResourceId.",
        )
        _args_schema.top = AAZIntArg(
            options=["--top"],
            help="The number of items to be included in the result.",
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        condition_0 = has_value(self.ctx.args.resource_group) and has_value(self.ctx.subscription_id)
        condition_1 = has_value(self.ctx.subscription_id) and has_value(self.ctx.args.resource_group) is not True
        if condition_0:
            self.WorkflowsListByResourceGroup(ctx=self.ctx)()
        if condition_1:
            self.WorkflowsListBySubscription(ctx=self.ctx)()
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

    class WorkflowsListByResourceGroup(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Logic/workflows",
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
                    "$filter", self.ctx.args.filter,
                ),
                **self.serialize_query_param(
                    "$top", self.ctx.args.top,
                ),
                **self.serialize_query_param(
                    "api-version", "2019-05-01",
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
            _element.id = AAZStrType(
                flags={"read_only": True},
            )
            _element.identity = AAZObjectType()
            _element.location = AAZStrType()
            _element.name = AAZStrType(
                flags={"read_only": True},
            )
            _element.properties = AAZObjectType(
                flags={"client_flatten": True},
            )
            _element.tags = AAZDictType()
            _element.type = AAZStrType(
                flags={"read_only": True},
            )

            identity = cls._schema_on_200.value.Element.identity
            identity.principal_id = AAZStrType(
                serialized_name="principalId",
                flags={"read_only": True},
            )
            identity.tenant_id = AAZStrType(
                serialized_name="tenantId",
                flags={"read_only": True},
            )
            identity.type = AAZStrType(
                flags={"required": True},
            )
            identity.user_assigned_identities = AAZDictType(
                serialized_name="userAssignedIdentities",
            )

            user_assigned_identities = cls._schema_on_200.value.Element.identity.user_assigned_identities
            user_assigned_identities.Element = AAZObjectType()

            _element = cls._schema_on_200.value.Element.identity.user_assigned_identities.Element
            _element.client_id = AAZStrType(
                serialized_name="clientId",
                flags={"read_only": True},
            )
            _element.principal_id = AAZStrType(
                serialized_name="principalId",
                flags={"read_only": True},
            )

            properties = cls._schema_on_200.value.Element.properties
            properties.access_control = AAZObjectType(
                serialized_name="accessControl",
            )
            properties.access_endpoint = AAZStrType(
                serialized_name="accessEndpoint",
                flags={"read_only": True},
            )
            properties.changed_time = AAZStrType(
                serialized_name="changedTime",
                flags={"read_only": True},
            )
            properties.created_time = AAZStrType(
                serialized_name="createdTime",
                flags={"read_only": True},
            )
            properties.definition = AAZFreeFormDictType()
            properties.endpoints_configuration = AAZObjectType(
                serialized_name="endpointsConfiguration",
            )
            properties.integration_account = AAZObjectType(
                serialized_name="integrationAccount",
            )
            _ListHelper._build_schema_resource_reference_read(properties.integration_account)
            properties.integration_service_environment = AAZObjectType(
                serialized_name="integrationServiceEnvironment",
            )
            _ListHelper._build_schema_resource_reference_read(properties.integration_service_environment)
            properties.provisioning_state = AAZStrType(
                serialized_name="provisioningState",
            )
            properties.sku = AAZObjectType()
            properties.state = AAZStrType()
            properties.version = AAZStrType(
                flags={"read_only": True},
            )

            access_control = cls._schema_on_200.value.Element.properties.access_control
            access_control.actions = AAZObjectType()
            _ListHelper._build_schema_flow_access_control_configuration_policy_read(access_control.actions)
            access_control.contents = AAZObjectType()
            _ListHelper._build_schema_flow_access_control_configuration_policy_read(access_control.contents)
            access_control.triggers = AAZObjectType()
            _ListHelper._build_schema_flow_access_control_configuration_policy_read(access_control.triggers)
            access_control.workflow_management = AAZObjectType(
                serialized_name="workflowManagement",
            )
            _ListHelper._build_schema_flow_access_control_configuration_policy_read(access_control.workflow_management)

            endpoints_configuration = cls._schema_on_200.value.Element.properties.endpoints_configuration
            endpoints_configuration.connector = AAZObjectType()
            _ListHelper._build_schema_flow_endpoints_read(endpoints_configuration.connector)
            endpoints_configuration.workflow = AAZObjectType()
            _ListHelper._build_schema_flow_endpoints_read(endpoints_configuration.workflow)

            sku = cls._schema_on_200.value.Element.properties.sku
            sku.name = AAZStrType(
                flags={"required": True},
            )
            sku.plan = AAZObjectType()
            _ListHelper._build_schema_resource_reference_read(sku.plan)

            tags = cls._schema_on_200.value.Element.tags
            tags.Element = AAZStrType()

            return cls._schema_on_200

    class WorkflowsListBySubscription(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/providers/Microsoft.Logic/workflows",
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
                    "$filter", self.ctx.args.filter,
                ),
                **self.serialize_query_param(
                    "$top", self.ctx.args.top,
                ),
                **self.serialize_query_param(
                    "api-version", "2019-05-01",
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
            _element.id = AAZStrType(
                flags={"read_only": True},
            )
            _element.identity = AAZObjectType()
            _element.location = AAZStrType()
            _element.name = AAZStrType(
                flags={"read_only": True},
            )
            _element.properties = AAZObjectType(
                flags={"client_flatten": True},
            )
            _element.tags = AAZDictType()
            _element.type = AAZStrType(
                flags={"read_only": True},
            )

            identity = cls._schema_on_200.value.Element.identity
            identity.principal_id = AAZStrType(
                serialized_name="principalId",
                flags={"read_only": True},
            )
            identity.tenant_id = AAZStrType(
                serialized_name="tenantId",
                flags={"read_only": True},
            )
            identity.type = AAZStrType(
                flags={"required": True},
            )
            identity.user_assigned_identities = AAZDictType(
                serialized_name="userAssignedIdentities",
            )

            user_assigned_identities = cls._schema_on_200.value.Element.identity.user_assigned_identities
            user_assigned_identities.Element = AAZObjectType()

            _element = cls._schema_on_200.value.Element.identity.user_assigned_identities.Element
            _element.client_id = AAZStrType(
                serialized_name="clientId",
                flags={"read_only": True},
            )
            _element.principal_id = AAZStrType(
                serialized_name="principalId",
                flags={"read_only": True},
            )

            properties = cls._schema_on_200.value.Element.properties
            properties.access_control = AAZObjectType(
                serialized_name="accessControl",
            )
            properties.access_endpoint = AAZStrType(
                serialized_name="accessEndpoint",
                flags={"read_only": True},
            )
            properties.changed_time = AAZStrType(
                serialized_name="changedTime",
                flags={"read_only": True},
            )
            properties.created_time = AAZStrType(
                serialized_name="createdTime",
                flags={"read_only": True},
            )
            properties.definition = AAZFreeFormDictType()
            properties.endpoints_configuration = AAZObjectType(
                serialized_name="endpointsConfiguration",
            )
            properties.integration_account = AAZObjectType(
                serialized_name="integrationAccount",
            )
            _ListHelper._build_schema_resource_reference_read(properties.integration_account)
            properties.integration_service_environment = AAZObjectType(
                serialized_name="integrationServiceEnvironment",
            )
            _ListHelper._build_schema_resource_reference_read(properties.integration_service_environment)
            properties.provisioning_state = AAZStrType(
                serialized_name="provisioningState",
            )
            properties.sku = AAZObjectType()
            properties.state = AAZStrType()
            properties.version = AAZStrType(
                flags={"read_only": True},
            )

            access_control = cls._schema_on_200.value.Element.properties.access_control
            access_control.actions = AAZObjectType()
            _ListHelper._build_schema_flow_access_control_configuration_policy_read(access_control.actions)
            access_control.contents = AAZObjectType()
            _ListHelper._build_schema_flow_access_control_configuration_policy_read(access_control.contents)
            access_control.triggers = AAZObjectType()
            _ListHelper._build_schema_flow_access_control_configuration_policy_read(access_control.triggers)
            access_control.workflow_management = AAZObjectType(
                serialized_name="workflowManagement",
            )
            _ListHelper._build_schema_flow_access_control_configuration_policy_read(access_control.workflow_management)

            endpoints_configuration = cls._schema_on_200.value.Element.properties.endpoints_configuration
            endpoints_configuration.connector = AAZObjectType()
            _ListHelper._build_schema_flow_endpoints_read(endpoints_configuration.connector)
            endpoints_configuration.workflow = AAZObjectType()
            _ListHelper._build_schema_flow_endpoints_read(endpoints_configuration.workflow)

            sku = cls._schema_on_200.value.Element.properties.sku
            sku.name = AAZStrType(
                flags={"required": True},
            )
            sku.plan = AAZObjectType()
            _ListHelper._build_schema_resource_reference_read(sku.plan)

            tags = cls._schema_on_200.value.Element.tags
            tags.Element = AAZStrType()

            return cls._schema_on_200


class _ListHelper:
    """Helper class for List"""

    _schema_flow_access_control_configuration_policy_read = None

    @classmethod
    def _build_schema_flow_access_control_configuration_policy_read(cls, _schema):
        if cls._schema_flow_access_control_configuration_policy_read is not None:
            _schema.allowed_caller_ip_addresses = cls._schema_flow_access_control_configuration_policy_read.allowed_caller_ip_addresses
            _schema.open_authentication_policies = cls._schema_flow_access_control_configuration_policy_read.open_authentication_policies
            return

        cls._schema_flow_access_control_configuration_policy_read = _schema_flow_access_control_configuration_policy_read = AAZObjectType()

        flow_access_control_configuration_policy_read = _schema_flow_access_control_configuration_policy_read
        flow_access_control_configuration_policy_read.allowed_caller_ip_addresses = AAZListType(
            serialized_name="allowedCallerIpAddresses",
        )
        flow_access_control_configuration_policy_read.open_authentication_policies = AAZObjectType(
            serialized_name="openAuthenticationPolicies",
        )

        allowed_caller_ip_addresses = _schema_flow_access_control_configuration_policy_read.allowed_caller_ip_addresses
        allowed_caller_ip_addresses.Element = AAZObjectType()

        _element = _schema_flow_access_control_configuration_policy_read.allowed_caller_ip_addresses.Element
        _element.address_range = AAZStrType(
            serialized_name="addressRange",
        )

        open_authentication_policies = _schema_flow_access_control_configuration_policy_read.open_authentication_policies
        open_authentication_policies.policies = AAZDictType()

        policies = _schema_flow_access_control_configuration_policy_read.open_authentication_policies.policies
        policies.Element = AAZObjectType()

        _element = _schema_flow_access_control_configuration_policy_read.open_authentication_policies.policies.Element
        _element.claims = AAZListType()
        _element.type = AAZStrType()

        claims = _schema_flow_access_control_configuration_policy_read.open_authentication_policies.policies.Element.claims
        claims.Element = AAZObjectType()

        _element = _schema_flow_access_control_configuration_policy_read.open_authentication_policies.policies.Element.claims.Element
        _element.name = AAZStrType()
        _element.value = AAZStrType()

        _schema.allowed_caller_ip_addresses = cls._schema_flow_access_control_configuration_policy_read.allowed_caller_ip_addresses
        _schema.open_authentication_policies = cls._schema_flow_access_control_configuration_policy_read.open_authentication_policies

    _schema_flow_endpoints_read = None

    @classmethod
    def _build_schema_flow_endpoints_read(cls, _schema):
        if cls._schema_flow_endpoints_read is not None:
            _schema.access_endpoint_ip_addresses = cls._schema_flow_endpoints_read.access_endpoint_ip_addresses
            _schema.outgoing_ip_addresses = cls._schema_flow_endpoints_read.outgoing_ip_addresses
            return

        cls._schema_flow_endpoints_read = _schema_flow_endpoints_read = AAZObjectType()

        flow_endpoints_read = _schema_flow_endpoints_read
        flow_endpoints_read.access_endpoint_ip_addresses = AAZListType(
            serialized_name="accessEndpointIpAddresses",
        )
        flow_endpoints_read.outgoing_ip_addresses = AAZListType(
            serialized_name="outgoingIpAddresses",
        )

        access_endpoint_ip_addresses = _schema_flow_endpoints_read.access_endpoint_ip_addresses
        access_endpoint_ip_addresses.Element = AAZObjectType()
        cls._build_schema_ip_address_read(access_endpoint_ip_addresses.Element)

        outgoing_ip_addresses = _schema_flow_endpoints_read.outgoing_ip_addresses
        outgoing_ip_addresses.Element = AAZObjectType()
        cls._build_schema_ip_address_read(outgoing_ip_addresses.Element)

        _schema.access_endpoint_ip_addresses = cls._schema_flow_endpoints_read.access_endpoint_ip_addresses
        _schema.outgoing_ip_addresses = cls._schema_flow_endpoints_read.outgoing_ip_addresses

    _schema_ip_address_read = None

    @classmethod
    def _build_schema_ip_address_read(cls, _schema):
        if cls._schema_ip_address_read is not None:
            _schema.address = cls._schema_ip_address_read.address
            return

        cls._schema_ip_address_read = _schema_ip_address_read = AAZObjectType()

        ip_address_read = _schema_ip_address_read
        ip_address_read.address = AAZStrType()

        _schema.address = cls._schema_ip_address_read.address

    _schema_resource_reference_read = None

    @classmethod
    def _build_schema_resource_reference_read(cls, _schema):
        if cls._schema_resource_reference_read is not None:
            _schema.id = cls._schema_resource_reference_read.id
            _schema.name = cls._schema_resource_reference_read.name
            _schema.type = cls._schema_resource_reference_read.type
            return

        cls._schema_resource_reference_read = _schema_resource_reference_read = AAZObjectType()

        resource_reference_read = _schema_resource_reference_read
        resource_reference_read.id = AAZStrType()
        resource_reference_read.name = AAZStrType(
            flags={"read_only": True},
        )
        resource_reference_read.type = AAZStrType(
            flags={"read_only": True},
        )

        _schema.id = cls._schema_resource_reference_read.id
        _schema.name = cls._schema_resource_reference_read.name
        _schema.type = cls._schema_resource_reference_read.type


__all__ = ["List"]
