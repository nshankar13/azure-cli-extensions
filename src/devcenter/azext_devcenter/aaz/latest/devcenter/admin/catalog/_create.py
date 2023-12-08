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
    "devcenter admin catalog create",
)
class Create(AAZCommand):
    """Create a catalog.

    :example: Create using an Azure DevOps repository
        az devcenter admin catalog create --ado-git path="/templates" branch="main" secret-identifier="https://contosokv.vault.azure.net/secrets/CentralRepoPat" uri="https://contoso@dev.azure.com/contoso/contosoOrg/_git/centralrepo-fakecontoso" --name "CentralCatalog" --dev-center-name "Contoso" --resource-group "rg1"

    :example: Create using a GitHub repository
        az devcenter admin catalog create --git-hub path="/templates" branch="main" secret-identifier="https://contosokv.vault.azure.net/secrets/CentralRepoPat" uri="https://github.com/Contoso/centralrepo-fake.git" --name "CentralCatalog" --dev-center-name "Contoso" --resource-group "rg1"
    """

    _aaz_info = {
        "version": "2023-10-01-preview",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.devcenter/devcenters/{}/catalogs/{}", "2023-10-01-preview"],
        ]
    }

    AZ_SUPPORT_NO_WAIT = True

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
        _args_schema.catalog_name = AAZStrArg(
            options=["-n", "--name", "--catalog-name"],
            help="The name of the catalog.",
            required=True,
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
            fmt=AAZStrArgFormat(
                pattern="^[a-zA-Z0-9][a-zA-Z0-9-]{2,25}$",
                max_length=26,
                min_length=3,
            ),
        )
        _args_schema.resource_group = AAZResourceGroupNameArg(
            required=True,
        )

        # define Arg Group "Properties"

        _args_schema = cls._args_schema
        _args_schema.ado_git = AAZObjectArg(
            options=["--ado-git"],
            arg_group="Properties",
            help="Properties for an Azure DevOps catalog type.",
        )
        cls._build_args_git_catalog_create(_args_schema.ado_git)
        _args_schema.git_hub = AAZObjectArg(
            options=["--git-hub"],
            arg_group="Properties",
            help="Properties for a GitHub catalog type.",
        )
        cls._build_args_git_catalog_create(_args_schema.git_hub)
        _args_schema.sync_type = AAZStrArg(
            options=["--sync-type"],
            arg_group="Properties",
            help="Indicates the type of sync that is configured for the catalog.",
            enum={"Manual": "Manual", "Scheduled": "Scheduled"},
        )
        return cls._args_schema

    _args_git_catalog_create = None

    @classmethod
    def _build_args_git_catalog_create(cls, _schema):
        if cls._args_git_catalog_create is not None:
            _schema.branch = cls._args_git_catalog_create.branch
            _schema.path = cls._args_git_catalog_create.path
            _schema.secret_identifier = cls._args_git_catalog_create.secret_identifier
            _schema.uri = cls._args_git_catalog_create.uri
            return

        cls._args_git_catalog_create = AAZObjectArg()

        git_catalog_create = cls._args_git_catalog_create
        git_catalog_create.branch = AAZStrArg(
            options=["branch"],
            help="Git branch.",
        )
        git_catalog_create.path = AAZStrArg(
            options=["path"],
            help="The folder where the catalog items can be found inside the repository.",
        )
        git_catalog_create.secret_identifier = AAZStrArg(
            options=["secret-identifier"],
            help="A reference to the Key Vault secret containing a security token to authenticate to a Git repository.",
        )
        git_catalog_create.uri = AAZStrArg(
            options=["uri"],
            help="Git URI.",
        )

        _schema.branch = cls._args_git_catalog_create.branch
        _schema.path = cls._args_git_catalog_create.path
        _schema.secret_identifier = cls._args_git_catalog_create.secret_identifier
        _schema.uri = cls._args_git_catalog_create.uri

    def _execute_operations(self):
        self.pre_operations()
        yield self.CatalogsCreateOrUpdate(ctx=self.ctx)()
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

    class CatalogsCreateOrUpdate(AAZHttpOperation):
        CLIENT_TYPE = "MgmtClient"

        def __call__(self, *args, **kwargs):
            request = self.make_request()
            session = self.client.send_request(request=request, stream=False, **kwargs)
            if session.http_response.status_code in [202]:
                return self.client.build_lro_polling(
                    self.ctx.args.no_wait,
                    session,
                    self.on_201,
                    self.on_error,
                    lro_options={"final-state-via": "azure-async-operation"},
                    path_format_arguments=self.url_parameters,
                )
            if session.http_response.status_code in [201]:
                return self.client.build_lro_polling(
                    self.ctx.args.no_wait,
                    session,
                    self.on_201,
                    self.on_error,
                    lro_options={"final-state-via": "azure-async-operation"},
                    path_format_arguments=self.url_parameters,
                )

            return self.on_error(session.http_response)

        @property
        def url(self):
            return self.client.format_url(
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevCenter/devcenters/{devCenterName}/catalogs/{catalogName}",
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
                typ=AAZObjectType,
                typ_kwargs={"flags": {"required": True, "client_flatten": True}}
            )
            _builder.set_prop("properties", AAZObjectType, typ_kwargs={"flags": {"client_flatten": True}})

            properties = _builder.get(".properties")
            if properties is not None:
                _CreateHelper._build_schema_git_catalog_create(properties.set_prop("adoGit", AAZObjectType, ".ado_git"))
                _CreateHelper._build_schema_git_catalog_create(properties.set_prop("gitHub", AAZObjectType, ".git_hub"))
                properties.set_prop("syncType", AAZStrType, ".sync_type")

            return self.serialize_content(_content_value)

        def on_201(self, session):
            data = self.deserialize_http_content(session)
            self.ctx.set_var(
                "instance",
                data,
                schema_builder=self._build_schema_on_201
            )

        _schema_on_201 = None

        @classmethod
        def _build_schema_on_201(cls):
            if cls._schema_on_201 is not None:
                return cls._schema_on_201

            cls._schema_on_201 = AAZObjectType()

            _schema_on_201 = cls._schema_on_201
            _schema_on_201.id = AAZStrType(
                flags={"read_only": True},
            )
            _schema_on_201.name = AAZStrType(
                flags={"read_only": True},
            )
            _schema_on_201.properties = AAZObjectType(
                flags={"client_flatten": True},
            )
            _schema_on_201.system_data = AAZObjectType(
                serialized_name="systemData",
                flags={"read_only": True},
            )
            _schema_on_201.type = AAZStrType(
                flags={"read_only": True},
            )

            properties = cls._schema_on_201.properties
            properties.ado_git = AAZObjectType(
                serialized_name="adoGit",
            )
            _CreateHelper._build_schema_git_catalog_read(properties.ado_git)
            properties.connection_state = AAZStrType(
                serialized_name="connectionState",
                flags={"read_only": True},
            )
            properties.git_hub = AAZObjectType(
                serialized_name="gitHub",
            )
            _CreateHelper._build_schema_git_catalog_read(properties.git_hub)
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

            last_sync_stats = cls._schema_on_201.properties.last_sync_stats
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

            system_data = cls._schema_on_201.system_data
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

            return cls._schema_on_201


class _CreateHelper:
    """Helper class for Create"""

    @classmethod
    def _build_schema_git_catalog_create(cls, _builder):
        if _builder is None:
            return
        _builder.set_prop("branch", AAZStrType, ".branch")
        _builder.set_prop("path", AAZStrType, ".path")
        _builder.set_prop("secretIdentifier", AAZStrType, ".secret_identifier")
        _builder.set_prop("uri", AAZStrType, ".uri")

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


__all__ = ["Create"]
