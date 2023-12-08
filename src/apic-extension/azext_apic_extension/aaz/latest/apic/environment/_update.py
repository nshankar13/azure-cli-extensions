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
    "apic environment update",
)
class Update(AAZCommand):
    """Update new or updates existing environment.

    :example: Update environment
        az apic environment update -g api-center-test -s contosoeuap --name public --title "Public cloud"
    """

    _aaz_info = {
        "version": "2024-03-01",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.apicenter/services/{}/workspaces/{}/environments/{}", "2024-03-01"],
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
        _args_schema.environment_name = AAZStrArg(
            options=["--name", "--environment", "--environment-name"],
            help="The name of the environment.",
            required=True,
            id_part="child_name_2",
            fmt=AAZStrArgFormat(
                max_length=90,
                min_length=1,
            ),
        )
        _args_schema.resource_group = AAZResourceGroupNameArg(
            required=True,
        )
        _args_schema.service_name = AAZStrArg(
            options=["-s", "--service", "--service-name"],
            help="The name of the API Center service.",
            required=True,
            id_part="name",
            fmt=AAZStrArgFormat(
                max_length=90,
                min_length=1,
            ),
        )
        _args_schema.workspace_name = AAZStrArg(
            options=["-w", "--workspace", "--workspace-name"],
            help="The name of the workspace.",
            required=True,
            id_part="child_name_1",
            fmt=AAZStrArgFormat(
                max_length=90,
                min_length=1,
            ),
        )

        # define Arg Group "Properties"

        _args_schema = cls._args_schema
        _args_schema.custom_properties = AAZObjectArg(
            options=["--custom-properties"],
            arg_group="Properties",
            help="The custom metadata defined for API catalog entities.",
            nullable=True,
            blank={},
        )
        _args_schema.description = AAZStrArg(
            options=["--description"],
            arg_group="Properties",
            help="Description.",
            nullable=True,
        )
        _args_schema.kind = AAZStrArg(
            options=["--kind"],
            arg_group="Properties",
            help="Environment kind.",
            enum={"development": "development", "production": "production", "staging": "staging", "testing": "testing"},
        )
        _args_schema.onboarding = AAZObjectArg(
            options=["--onboarding"],
            arg_group="Properties",
            nullable=True,
        )
        _args_schema.server = AAZObjectArg(
            options=["--server"],
            arg_group="Properties",
            help="Server information of the environment.",
            nullable=True,
        )
        _args_schema.title = AAZStrArg(
            options=["--title"],
            arg_group="Properties",
            help="Environment title.",
            fmt=AAZStrArgFormat(
                max_length=50,
                min_length=1,
            ),
        )

        onboarding = cls._args_schema.onboarding
        onboarding.developer_portal_uri = AAZListArg(
            options=["developer-portal-uri"],
            nullable=True,
        )
        onboarding.instructions = AAZStrArg(
            options=["instructions"],
            help="Onboarding guide.",
            nullable=True,
        )

        developer_portal_uri = cls._args_schema.onboarding.developer_portal_uri
        developer_portal_uri.Element = AAZStrArg(
            nullable=True,
        )

        server = cls._args_schema.server
        server.management_portal_uri = AAZListArg(
            options=["management-portal-uri"],
            nullable=True,
        )
        server.type = AAZStrArg(
            options=["type"],
            help="Type of the server that represents the environment.",
            nullable=True,
            enum={"AWS API Gateway": "AWS API Gateway", "Apigee API Management": "Apigee API Management", "Azure API Management": "Azure API Management", "Azure compute service": "Azure compute service", "Kong API Gateway": "Kong API Gateway", "Kubernetes": "Kubernetes", "MuleSoft API Management": "MuleSoft API Management"},
        )

        management_portal_uri = cls._args_schema.server.management_portal_uri
        management_portal_uri.Element = AAZStrArg(
            nullable=True,
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        self.EnvironmentsGet(ctx=self.ctx)()
        self.pre_instance_update(self.ctx.vars.instance)
        self.InstanceUpdateByJson(ctx=self.ctx)()
        self.InstanceUpdateByGeneric(ctx=self.ctx)()
        self.post_instance_update(self.ctx.vars.instance)
        self.EnvironmentsCreateOrUpdate(ctx=self.ctx)()
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

    class EnvironmentsGet(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiCenter/services/{serviceName}/workspaces/{workspaceName}/environments/{environmentName}",
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
                    "environmentName", self.ctx.args.environment_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "resourceGroupName", self.ctx.args.resource_group,
                    required=True,
                ),
                **self.serialize_url_param(
                    "serviceName", self.ctx.args.service_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "subscriptionId", self.ctx.subscription_id,
                    required=True,
                ),
                **self.serialize_url_param(
                    "workspaceName", self.ctx.args.workspace_name,
                    required=True,
                ),
            }
            return parameters

        @property
        def query_parameters(self):
            parameters = {
                **self.serialize_query_param(
                    "api-version", "2024-03-01",
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
            _UpdateHelper._build_schema_environment_read(cls._schema_on_200)

            return cls._schema_on_200

    class EnvironmentsCreateOrUpdate(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiCenter/services/{serviceName}/workspaces/{workspaceName}/environments/{environmentName}",
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
                    "environmentName", self.ctx.args.environment_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "resourceGroupName", self.ctx.args.resource_group,
                    required=True,
                ),
                **self.serialize_url_param(
                    "serviceName", self.ctx.args.service_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "subscriptionId", self.ctx.subscription_id,
                    required=True,
                ),
                **self.serialize_url_param(
                    "workspaceName", self.ctx.args.workspace_name,
                    required=True,
                ),
            }
            return parameters

        @property
        def query_parameters(self):
            parameters = {
                **self.serialize_query_param(
                    "api-version", "2024-03-01",
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
            _UpdateHelper._build_schema_environment_read(cls._schema_on_200_201)

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
                properties.set_prop("customProperties", AAZObjectType, ".custom_properties")
                properties.set_prop("description", AAZStrType, ".description")
                properties.set_prop("kind", AAZStrType, ".kind", typ_kwargs={"flags": {"required": True}})
                properties.set_prop("onboarding", AAZObjectType, ".onboarding")
                properties.set_prop("server", AAZObjectType, ".server")
                properties.set_prop("title", AAZStrType, ".title", typ_kwargs={"flags": {"required": True}})

            onboarding = _builder.get(".properties.onboarding")
            if onboarding is not None:
                onboarding.set_prop("developerPortalUri", AAZListType, ".developer_portal_uri")
                onboarding.set_prop("instructions", AAZStrType, ".instructions")

            developer_portal_uri = _builder.get(".properties.onboarding.developerPortalUri")
            if developer_portal_uri is not None:
                developer_portal_uri.set_elements(AAZStrType, ".")

            server = _builder.get(".properties.server")
            if server is not None:
                server.set_prop("managementPortalUri", AAZListType, ".management_portal_uri")
                server.set_prop("type", AAZStrType, ".type")

            management_portal_uri = _builder.get(".properties.server.managementPortalUri")
            if management_portal_uri is not None:
                management_portal_uri.set_elements(AAZStrType, ".")

            return _instance_value

    class InstanceUpdateByGeneric(AAZGenericInstanceUpdateOperation):

        def __call__(self, *args, **kwargs):
            self._update_instance_by_generic(
                self.ctx.vars.instance,
                self.ctx.generic_update_args
            )


class _UpdateHelper:
    """Helper class for Update"""

    _schema_environment_read = None

    @classmethod
    def _build_schema_environment_read(cls, _schema):
        if cls._schema_environment_read is not None:
            _schema.id = cls._schema_environment_read.id
            _schema.name = cls._schema_environment_read.name
            _schema.properties = cls._schema_environment_read.properties
            _schema.system_data = cls._schema_environment_read.system_data
            _schema.type = cls._schema_environment_read.type
            return

        cls._schema_environment_read = _schema_environment_read = AAZObjectType()

        environment_read = _schema_environment_read
        environment_read.id = AAZStrType(
            flags={"read_only": True},
        )
        environment_read.name = AAZStrType(
            flags={"read_only": True},
        )
        environment_read.properties = AAZObjectType(
            flags={"client_flatten": True},
        )
        environment_read.system_data = AAZObjectType(
            serialized_name="systemData",
            flags={"read_only": True},
        )
        environment_read.type = AAZStrType(
            flags={"read_only": True},
        )

        properties = _schema_environment_read.properties
        properties.custom_properties = AAZObjectType(
            serialized_name="customProperties",
        )
        properties.description = AAZStrType()
        properties.kind = AAZStrType(
            flags={"required": True},
        )
        properties.onboarding = AAZObjectType()
        properties.server = AAZObjectType()
        properties.title = AAZStrType(
            flags={"required": True},
        )

        onboarding = _schema_environment_read.properties.onboarding
        onboarding.developer_portal_uri = AAZListType(
            serialized_name="developerPortalUri",
        )
        onboarding.instructions = AAZStrType()

        developer_portal_uri = _schema_environment_read.properties.onboarding.developer_portal_uri
        developer_portal_uri.Element = AAZStrType()

        server = _schema_environment_read.properties.server
        server.management_portal_uri = AAZListType(
            serialized_name="managementPortalUri",
        )
        server.type = AAZStrType()

        management_portal_uri = _schema_environment_read.properties.server.management_portal_uri
        management_portal_uri.Element = AAZStrType()

        system_data = _schema_environment_read.system_data
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

        _schema.id = cls._schema_environment_read.id
        _schema.name = cls._schema_environment_read.name
        _schema.properties = cls._schema_environment_read.properties
        _schema.system_data = cls._schema_environment_read.system_data
        _schema.type = cls._schema_environment_read.type


__all__ = ["Update"]
