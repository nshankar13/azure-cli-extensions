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
    "logic workflow identity assign",
)
class Assign(AAZCommand):
    """Assign identities
    """

    _aaz_info = {
        "version": "2019-05-01",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.logic/workflows/{}", "2019-05-01", "identity"],
        ]
    }

    def _handler(self, command_args):
        super()._handler(command_args)
        self.SubresourceSelector(ctx=self.ctx, name="subresource")
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
        _args_schema.resource_group = AAZResourceGroupNameArg(
            required=True,
        )
        _args_schema.name = AAZStrArg(
            options=["--name"],
            help="The workflow name.",
            required=True,
        )

        # define Arg Group "Workflow.identity"

        _args_schema = cls._args_schema
        _args_schema.type = AAZStrArg(
            options=["--type"],
            arg_group="Workflow.identity",
            help="Type of managed service identity. The type 'SystemAssigned' includes an implicitly created identity. The type 'None' will remove any identities from the resource.",
            required=True,
            enum={"None": "None", "SystemAssigned": "SystemAssigned", "UserAssigned": "UserAssigned"},
        )
        _args_schema.user_assigned_identities = AAZDictArg(
            options=["--user-assigned-identities"],
            arg_group="Workflow.identity",
            help="The list of user assigned identities associated with the resource. The user identity dictionary key references will be ARM resource ids in the form: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName}",
        )

        user_assigned_identities = cls._args_schema.user_assigned_identities
        user_assigned_identities.Element = AAZObjectArg(
            blank={},
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        self.WorkflowsGet(ctx=self.ctx)()
        self.pre_instance_create()
        self.InstanceCreateByJson(ctx=self.ctx)()
        self.post_instance_create(self.ctx.selectors.subresource.required())
        self.WorkflowsCreateOrUpdate(ctx=self.ctx)()
        self.post_operations()

    @register_callback
    def pre_operations(self):
        pass

    @register_callback
    def post_operations(self):
        pass

    @register_callback
    def pre_instance_create(self):
        pass

    @register_callback
    def post_instance_create(self, instance):
        pass

    def _output(self, *args, **kwargs):
        result = self.deserialize_output(self.ctx.selectors.subresource.required(), client_flatten=True)
        return result

    class SubresourceSelector(AAZJsonSelector):

        def _get(self):
            result = self.ctx.vars.instance
            return result.identity

        def _set(self, value):
            result = self.ctx.vars.instance
            result.identity = value
            return

    class WorkflowsGet(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Logic/workflows/{workflowName}",
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
                **self.serialize_url_param(
                    "workflowName", self.ctx.args.name,
                    required=True,
                ),
            }
            return parameters

        @property
        def query_parameters(self):
            parameters = {
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
            _AssignHelper._build_schema_workflow_read(cls._schema_on_200)

            return cls._schema_on_200

    class WorkflowsCreateOrUpdate(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Logic/workflows/{workflowName}",
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
                    "resourceGroupName", self.ctx.args.resource_group,
                    required=True,
                ),
                **self.serialize_url_param(
                    "subscriptionId", self.ctx.subscription_id,
                    required=True,
                ),
                **self.serialize_url_param(
                    "workflowName", self.ctx.args.name,
                    required=True,
                ),
            }
            return parameters

        @property
        def query_parameters(self):
            parameters = {
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
            _AssignHelper._build_schema_workflow_read(cls._schema_on_200_201)

            return cls._schema_on_200_201

    class InstanceCreateByJson(AAZJsonInstanceCreateOperation):

        def __call__(self, *args, **kwargs):
            self.ctx.selectors.subresource.set(self._create_instance())

        def _create_instance(self):
            _instance_value, _builder = self.new_content_builder(
                self.ctx.args,
                typ=AAZObjectType
            )
            _builder.set_prop("type", AAZStrType, ".type", typ_kwargs={"flags": {"required": True}})
            _builder.set_prop("userAssignedIdentities", AAZDictType, ".user_assigned_identities")

            user_assigned_identities = _builder.get(".userAssignedIdentities")
            if user_assigned_identities is not None:
                user_assigned_identities.set_elements(AAZObjectType, ".")

            return _instance_value


class _AssignHelper:
    """Helper class for Assign"""

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

    _schema_workflow_read = None

    @classmethod
    def _build_schema_workflow_read(cls, _schema):
        if cls._schema_workflow_read is not None:
            _schema.id = cls._schema_workflow_read.id
            _schema.identity = cls._schema_workflow_read.identity
            _schema.location = cls._schema_workflow_read.location
            _schema.name = cls._schema_workflow_read.name
            _schema.properties = cls._schema_workflow_read.properties
            _schema.tags = cls._schema_workflow_read.tags
            _schema.type = cls._schema_workflow_read.type
            return

        cls._schema_workflow_read = _schema_workflow_read = AAZObjectType()

        workflow_read = _schema_workflow_read
        workflow_read.id = AAZStrType(
            flags={"read_only": True},
        )
        workflow_read.identity = AAZObjectType()
        workflow_read.location = AAZStrType()
        workflow_read.name = AAZStrType(
            flags={"read_only": True},
        )
        workflow_read.properties = AAZObjectType(
            flags={"client_flatten": True},
        )
        workflow_read.tags = AAZDictType()
        workflow_read.type = AAZStrType(
            flags={"read_only": True},
        )

        identity = _schema_workflow_read.identity
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

        user_assigned_identities = _schema_workflow_read.identity.user_assigned_identities
        user_assigned_identities.Element = AAZObjectType()

        _element = _schema_workflow_read.identity.user_assigned_identities.Element
        _element.client_id = AAZStrType(
            serialized_name="clientId",
            flags={"read_only": True},
        )
        _element.principal_id = AAZStrType(
            serialized_name="principalId",
            flags={"read_only": True},
        )

        properties = _schema_workflow_read.properties
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
        cls._build_schema_resource_reference_read(properties.integration_account)
        properties.integration_service_environment = AAZObjectType(
            serialized_name="integrationServiceEnvironment",
        )
        cls._build_schema_resource_reference_read(properties.integration_service_environment)
        properties.provisioning_state = AAZStrType(
            serialized_name="provisioningState",
        )
        properties.sku = AAZObjectType()
        properties.state = AAZStrType()
        properties.version = AAZStrType(
            flags={"read_only": True},
        )

        access_control = _schema_workflow_read.properties.access_control
        access_control.actions = AAZObjectType()
        cls._build_schema_flow_access_control_configuration_policy_read(access_control.actions)
        access_control.contents = AAZObjectType()
        cls._build_schema_flow_access_control_configuration_policy_read(access_control.contents)
        access_control.triggers = AAZObjectType()
        cls._build_schema_flow_access_control_configuration_policy_read(access_control.triggers)
        access_control.workflow_management = AAZObjectType(
            serialized_name="workflowManagement",
        )
        cls._build_schema_flow_access_control_configuration_policy_read(access_control.workflow_management)

        endpoints_configuration = _schema_workflow_read.properties.endpoints_configuration
        endpoints_configuration.connector = AAZObjectType()
        cls._build_schema_flow_endpoints_read(endpoints_configuration.connector)
        endpoints_configuration.workflow = AAZObjectType()
        cls._build_schema_flow_endpoints_read(endpoints_configuration.workflow)

        sku = _schema_workflow_read.properties.sku
        sku.name = AAZStrType(
            flags={"required": True},
        )
        sku.plan = AAZObjectType()
        cls._build_schema_resource_reference_read(sku.plan)

        tags = _schema_workflow_read.tags
        tags.Element = AAZStrType()

        _schema.id = cls._schema_workflow_read.id
        _schema.identity = cls._schema_workflow_read.identity
        _schema.location = cls._schema_workflow_read.location
        _schema.name = cls._schema_workflow_read.name
        _schema.properties = cls._schema_workflow_read.properties
        _schema.tags = cls._schema_workflow_read.tags
        _schema.type = cls._schema_workflow_read.type


__all__ = ["Assign"]
