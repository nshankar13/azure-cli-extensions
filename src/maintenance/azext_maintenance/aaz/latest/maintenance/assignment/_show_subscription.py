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
    "maintenance assignment show-subscription",
    is_experimental=True,
)
class ShowSubscription(AAZCommand):
    """Get configuration assignment for resource..

    :example: ConfigurationAssignments_GetSubscription
        az maintenance assignment show-subscription --name "example1"
    """

    _aaz_info = {
        "version": "2023-04-01",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/providers/microsoft.maintenance/configurationassignments/{}", "2023-04-01"],
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
        _args_schema.configuration_assignment_name = AAZStrArg(
            options=["-n", "--name", "--configuration-assignment-name"],
            help="Configuration assignment name",
            required=True,
            id_part="name",
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        self.ConfigurationAssignmentsForSubscriptionsGet(ctx=self.ctx)()
        self.post_operations()

    @register_callback
    def pre_operations(self):
        pass

    @register_callback
    def post_operations(self):
        pass

    def _output(self, *args, **kwargs):
        result = self.deserialize_output(self.ctx.vars.instance, client_flatten=True)
        return result

    class ConfigurationAssignmentsForSubscriptionsGet(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/providers/Microsoft.Maintenance/configurationAssignments/{configurationAssignmentName}",
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
                    "configurationAssignmentName", self.ctx.args.configuration_assignment_name,
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
                    "api-version", "2023-04-01",
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
            _schema_on_200.id = AAZStrType(
                flags={"read_only": True},
            )
            _schema_on_200.location = AAZStrType()
            _schema_on_200.name = AAZStrType(
                flags={"read_only": True},
            )
            _schema_on_200.properties = AAZObjectType(
                flags={"client_flatten": True},
            )
            _schema_on_200.system_data = AAZObjectType(
                serialized_name="systemData",
                flags={"read_only": True},
            )
            _schema_on_200.type = AAZStrType(
                flags={"read_only": True},
            )

            properties = cls._schema_on_200.properties
            properties.filter = AAZObjectType()
            properties.maintenance_configuration_id = AAZStrType(
                serialized_name="maintenanceConfigurationId",
            )
            properties.resource_id = AAZStrType(
                serialized_name="resourceId",
            )

            filter = cls._schema_on_200.properties.filter
            filter.locations = AAZListType()
            filter.os_types = AAZListType(
                serialized_name="osTypes",
            )
            filter.resource_groups = AAZListType(
                serialized_name="resourceGroups",
            )
            filter.resource_types = AAZListType(
                serialized_name="resourceTypes",
            )
            filter.tag_settings = AAZObjectType(
                serialized_name="tagSettings",
            )

            locations = cls._schema_on_200.properties.filter.locations
            locations.Element = AAZStrType()

            os_types = cls._schema_on_200.properties.filter.os_types
            os_types.Element = AAZStrType()

            resource_groups = cls._schema_on_200.properties.filter.resource_groups
            resource_groups.Element = AAZStrType()

            resource_types = cls._schema_on_200.properties.filter.resource_types
            resource_types.Element = AAZStrType()

            tag_settings = cls._schema_on_200.properties.filter.tag_settings
            tag_settings.filter_operator = AAZStrType(
                serialized_name="filterOperator",
            )
            tag_settings.tags = AAZDictType()

            tags = cls._schema_on_200.properties.filter.tag_settings.tags
            tags.Element = AAZListType()

            _element = cls._schema_on_200.properties.filter.tag_settings.tags.Element
            _element.Element = AAZStrType()

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

            return cls._schema_on_200


class _ShowSubscriptionHelper:
    """Helper class for ShowSubscription"""


__all__ = ["ShowSubscription"]
