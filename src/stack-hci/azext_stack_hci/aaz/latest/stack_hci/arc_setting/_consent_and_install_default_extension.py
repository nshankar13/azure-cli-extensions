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
    "stack-hci arc-setting consent-and-install-default-extension",
)
class ConsentAndInstallDefaultExtension(AAZCommand):
    """Add consent time for default extensions and initiate extensions installation

    :example: Consent and install default extension
        az stack-hci arc-setting consent-and-install-default-extension -g rg --arc-setting-name default --cluster-name name
    """

    _aaz_info = {
        "version": "2023-08-01",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.azurestackhci/clusters/{}/arcsettings/{}/consentandinstalldefaultextensions", "2023-08-01"],
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
        _args_schema.arc_setting_name = AAZStrArg(
            options=["--arc-setting-name"],
            help="The name of the proxy resource holding details of HCI ArcSetting information.",
            required=True,
            id_part="child_name_1",
        )
        _args_schema.cluster_name = AAZStrArg(
            options=["--cluster-name"],
            help="The name of the cluster.",
            required=True,
            id_part="name",
        )
        _args_schema.resource_group = AAZResourceGroupNameArg(
            required=True,
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        self.ArcSettingsConsentAndInstallDefaultExtensions(ctx=self.ctx)()
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

    class ArcSettingsConsentAndInstallDefaultExtensions(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AzureStackHCI/clusters/{clusterName}/arcSettings/{arcSettingName}/consentAndInstallDefaultExtensions",
                **self.url_parameters
            )

        @property
        def method(self):
            return "POST"

        @property
        def error_format(self):
            return "MgmtErrorFormat"

        @property
        def url_parameters(self):
            parameters = {
                **self.serialize_url_param(
                    "arcSettingName", self.ctx.args.arc_setting_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "clusterName", self.ctx.args.cluster_name,
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
                    "api-version", "2023-08-01",
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
            properties.aggregate_state = AAZStrType(
                serialized_name="aggregateState",
                flags={"read_only": True},
            )
            properties.arc_application_client_id = AAZStrType(
                serialized_name="arcApplicationClientId",
            )
            properties.arc_application_object_id = AAZStrType(
                serialized_name="arcApplicationObjectId",
            )
            properties.arc_application_tenant_id = AAZStrType(
                serialized_name="arcApplicationTenantId",
            )
            properties.arc_instance_resource_group = AAZStrType(
                serialized_name="arcInstanceResourceGroup",
            )
            properties.arc_service_principal_object_id = AAZStrType(
                serialized_name="arcServicePrincipalObjectId",
            )
            properties.connectivity_properties = AAZObjectType(
                serialized_name="connectivityProperties",
            )
            properties.default_extensions = AAZListType(
                serialized_name="defaultExtensions",
                flags={"read_only": True},
            )
            properties.per_node_details = AAZListType(
                serialized_name="perNodeDetails",
                flags={"read_only": True},
            )
            properties.provisioning_state = AAZStrType(
                serialized_name="provisioningState",
                flags={"read_only": True},
            )

            connectivity_properties = cls._schema_on_200.properties.connectivity_properties
            connectivity_properties.enabled = AAZBoolType()
            connectivity_properties.service_configurations = AAZListType(
                serialized_name="serviceConfigurations",
            )

            service_configurations = cls._schema_on_200.properties.connectivity_properties.service_configurations
            service_configurations.Element = AAZObjectType()

            _element = cls._schema_on_200.properties.connectivity_properties.service_configurations.Element
            _element.port = AAZIntType(
                flags={"required": True},
            )
            _element.service_name = AAZStrType(
                serialized_name="serviceName",
                flags={"required": True},
            )

            default_extensions = cls._schema_on_200.properties.default_extensions
            default_extensions.Element = AAZObjectType()

            _element = cls._schema_on_200.properties.default_extensions.Element
            _element.category = AAZStrType(
                flags={"read_only": True},
            )
            _element.consent_time = AAZStrType(
                serialized_name="consentTime",
                flags={"read_only": True},
            )

            per_node_details = cls._schema_on_200.properties.per_node_details
            per_node_details.Element = AAZObjectType()

            _element = cls._schema_on_200.properties.per_node_details.Element
            _element.arc_instance = AAZStrType(
                serialized_name="arcInstance",
                flags={"read_only": True},
            )
            _element.name = AAZStrType(
                flags={"read_only": True},
            )
            _element.state = AAZStrType(
                flags={"read_only": True},
            )

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


class _ConsentAndInstallDefaultExtensionHelper:
    """Helper class for ConsentAndInstallDefaultExtension"""


__all__ = ["ConsentAndInstallDefaultExtension"]
