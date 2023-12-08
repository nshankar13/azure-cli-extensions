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
    "devcenter admin catalog wait",
)
class Wait(AAZWaitCommand):
    """Place the CLI in a waiting state until a condition is met.
    """

    _aaz_info = {
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.devcenter/devcenters/{}/catalogs/{}", "2023-10-01-preview"],
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
        _args_schema.catalog_name = AAZStrArg(
            options=["-n", "--name", "--catalog-name"],
            help="The name of the catalog.",
            required=True,
            id_part="child_name_1",
            fmt=AAZStrArgFormat(
                pattern="^[a-zA-Z0-9][a-zA-Z0-9-_.]{2,62}$",
                max_length=63,
                min_length=3,
            ),
        )
        _args_schema.dev_center_name = AAZStrArg(
            options=["-d", "--dev-center", "--dev-center-name"],
            help="The name of the dev center. Use `az configure -d dev-center=<dev_center_name>` to configure a default.",
            required=True,
            id_part="name",
            fmt=AAZStrArgFormat(
                pattern="^[a-zA-Z0-9][a-zA-Z0-9-]{2,25}$",
                max_length=26,
                min_length=3,
            ),
        )
        _args_schema.resource_group = AAZResourceGroupNameArg(
            required=True,
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        self.CatalogsGet(ctx=self.ctx)()
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

    class CatalogsGet(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevCenter/devcenters/{devCenterName}/catalogs/{catalogName}",
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
                    "catalogName", self.ctx.args.catalog_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "devCenterName", self.ctx.args.dev_center_name,
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
            properties.ado_git = AAZObjectType(
                serialized_name="adoGit",
            )
            _WaitHelper._build_schema_git_catalog_read(properties.ado_git)
            properties.connection_state = AAZStrType(
                serialized_name="connectionState",
                flags={"read_only": True},
            )
            properties.git_hub = AAZObjectType(
                serialized_name="gitHub",
            )
            _WaitHelper._build_schema_git_catalog_read(properties.git_hub)
            properties.last_connection_time = AAZStrType(
                serialized_name="lastConnectionTime",
                flags={"read_only": True},
            )
            properties.last_sync_stats = AAZObjectType(
                serialized_name="lastSyncStats",
            )
            properties.last_sync_time = AAZStrType(
                serialized_name="lastSyncTime",
                flags={"read_only": True},
            )
            properties.provisioning_state = AAZStrType(
                serialized_name="provisioningState",
                flags={"read_only": True},
            )
            properties.sync_state = AAZStrType(
                serialized_name="syncState",
                flags={"read_only": True},
            )
            properties.sync_type = AAZStrType(
                serialized_name="syncType",
            )

            last_sync_stats = cls._schema_on_200.properties.last_sync_stats
            last_sync_stats.added = AAZIntType(
                flags={"read_only": True},
            )
            last_sync_stats.removed = AAZIntType(
                flags={"read_only": True},
            )
            last_sync_stats.synchronization_errors = AAZIntType(
                serialized_name="synchronizationErrors",
                flags={"read_only": True},
            )
            last_sync_stats.unchanged = AAZIntType(
                flags={"read_only": True},
            )
            last_sync_stats.updated = AAZIntType(
                flags={"read_only": True},
            )
            last_sync_stats.validation_errors = AAZIntType(
                serialized_name="validationErrors",
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


class _WaitHelper:
    """Helper class for Wait"""

    _schema_git_catalog_read = None

    @classmethod
    def _build_schema_git_catalog_read(cls, _schema):
        if cls._schema_git_catalog_read is not None:
            _schema.branch = cls._schema_git_catalog_read.branch
            _schema.path = cls._schema_git_catalog_read.path
            _schema.secret_identifier = cls._schema_git_catalog_read.secret_identifier
            _schema.uri = cls._schema_git_catalog_read.uri
            return

        cls._schema_git_catalog_read = _schema_git_catalog_read = AAZObjectType()

        git_catalog_read = _schema_git_catalog_read
        git_catalog_read.branch = AAZStrType()
        git_catalog_read.path = AAZStrType()
        git_catalog_read.secret_identifier = AAZStrType(
            serialized_name="secretIdentifier",
        )
        git_catalog_read.uri = AAZStrType()

        _schema.branch = cls._schema_git_catalog_read.branch
        _schema.path = cls._schema_git_catalog_read.path
        _schema.secret_identifier = cls._schema_git_catalog_read.secret_identifier
        _schema.uri = cls._schema_git_catalog_read.uri


__all__ = ["Wait"]
