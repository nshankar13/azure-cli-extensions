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
    "networkcloud cluster baremetalmachinekeyset update",
    is_preview=True,
)
class Update(AAZCommand):
    """Update properties of bare metal machine key set for the provided cluster, or update the tags associated with it. Properties and tag updates can be done independently.

    :example: Patch bare metal machine key set of cluster
        az networkcloud cluster baremetalmachinekeyset update --name "bareMetalMachineKeySetName" --expiration "2022-12-31T23:59:59.008Z" --jump-hosts-allowed "192.0.2.1" "192.0.2.5" --user-list "[{description:'User description',azureUserName:userABC,userPrincipalName:'userABC@myorg.com',sshPublicKey:{keyData:'ssh-rsa AAtsE3njSONzDYRIZv/WLjVuMfrUSByHp+/ojNZfpB3af/YDzwQCZzXnblrv9d3q4c2tWmm/SyFqthaqd0= admin@vm'}}]" --tags key1="myvalue1" key2="myvalue2" --cluster-name "clusterName" --resource-group "resourceGroupName"
    """

    _aaz_info = {
        "version": "2023-10-01-preview",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.networkcloud/clusters/{}/baremetalmachinekeysets/{}", "2023-10-01-preview"],
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
        _args_schema.bare_metal_machine_key_set_name = AAZStrArg(
            options=["-n", "--name", "--bare-metal-machine-key-set-name"],
            help="The name of the bare metal machine key set.",
            required=True,
            id_part="child_name_1",
            fmt=AAZStrArgFormat(
                pattern="^([a-zA-Z0-9][a-zA-Z0-9-_]{0,28}[a-zA-Z0-9])$",
            ),
        )
        _args_schema.cluster_name = AAZStrArg(
            options=["--cluster-name"],
            help="The name of the cluster.",
            required=True,
            id_part="name",
            fmt=AAZStrArgFormat(
                pattern="^([a-zA-Z0-9][a-zA-Z0-9-_]{0,28}[a-zA-Z0-9])$",
            ),
        )
        _args_schema.resource_group = AAZResourceGroupNameArg(
            required=True,
        )

        # define Arg Group "BareMetalMachineKeySetUpdateParameters"

        _args_schema = cls._args_schema
        _args_schema.tags = AAZDictArg(
            options=["--tags"],
            arg_group="BareMetalMachineKeySetUpdateParameters",
            help="The Azure resource tags that will replace the existing ones.",
        )

        tags = cls._args_schema.tags
        tags.Element = AAZStrArg()

        # define Arg Group "Properties"

        _args_schema = cls._args_schema
        _args_schema.expiration = AAZDateTimeArg(
            options=["--expiration"],
            arg_group="Properties",
            help="The date and time after which the users in this key set will be removed from the bare metal machines.",
        )
        _args_schema.jump_hosts_allowed = AAZListArg(
            options=["--jump-hosts-allowed"],
            arg_group="Properties",
            help="The list of IP addresses of jump hosts with management network access from which a login will be allowed for the users.",
        )
        _args_schema.user_list = AAZListArg(
            options=["--user-list"],
            arg_group="Properties",
            help="The unique list of permitted users.",
        )

        jump_hosts_allowed = cls._args_schema.jump_hosts_allowed
        jump_hosts_allowed.Element = AAZStrArg()

        user_list = cls._args_schema.user_list
        user_list.Element = AAZObjectArg()

        _element = cls._args_schema.user_list.Element
        _element.azure_user_name = AAZStrArg(
            options=["azure-user-name"],
            help="The user name that will be used for access.",
            required=True,
        )
        _element.description = AAZStrArg(
            options=["description"],
            help="The free-form description for this user.",
            fmt=AAZStrArgFormat(
                max_length=256,
            ),
        )
        _element.ssh_public_key = AAZObjectArg(
            options=["ssh-public-key"],
            help="The SSH public key for this user.",
            required=True,
        )
        _element.user_principal_name = AAZStrArg(
            options=["user-principal-name"],
            help="The user principal name (email format) used to validate this user's group membership.",
        )

        ssh_public_key = cls._args_schema.user_list.Element.ssh_public_key
        ssh_public_key.key_data = AAZStrArg(
            options=["key-data"],
            help="The public ssh key of the user.",
            required=True,
            fmt=AAZStrArgFormat(
                min_length=1,
            ),
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        yield self.BareMetalMachineKeySetsUpdate(ctx=self.ctx)()
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

    class BareMetalMachineKeySetsUpdate(AAZHttpOperation):
        CLIENT_TYPE = "MgmtClient"

        def __call__(self, *args, **kwargs):
            request = self.make_request()
            session = self.client.send_request(request=request, stream=False, **kwargs)
            if session.http_response.status_code in [202]:
                return self.client.build_lro_polling(
                    self.ctx.args.no_wait,
                    session,
                    self.on_200,
                    self.on_error,
                    lro_options={"final-state-via": "azure-async-operation"},
                    path_format_arguments=self.url_parameters,
                )
            if session.http_response.status_code in [200]:
                return self.client.build_lro_polling(
                    self.ctx.args.no_wait,
                    session,
                    self.on_200,
                    self.on_error,
                    lro_options={"final-state-via": "azure-async-operation"},
                    path_format_arguments=self.url_parameters,
                )

            return self.on_error(session.http_response)

        @property
        def url(self):
            return self.client.format_url(
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetworkCloud/clusters/{clusterName}/bareMetalMachineKeySets/{bareMetalMachineKeySetName}",
                **self.url_parameters
            )

        @property
        def method(self):
            return "PATCH"

        @property
        def error_format(self):
            return "MgmtErrorFormat"

        @property
        def url_parameters(self):
            parameters = {
                **self.serialize_url_param(
                    "bareMetalMachineKeySetName", self.ctx.args.bare_metal_machine_key_set_name,
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
                typ_kwargs={"flags": {"client_flatten": True}}
            )
            _builder.set_prop("properties", AAZObjectType, typ_kwargs={"flags": {"client_flatten": True}})
            _builder.set_prop("tags", AAZDictType, ".tags")

            properties = _builder.get(".properties")
            if properties is not None:
                properties.set_prop("expiration", AAZStrType, ".expiration")
                properties.set_prop("jumpHostsAllowed", AAZListType, ".jump_hosts_allowed")
                properties.set_prop("userList", AAZListType, ".user_list")

            jump_hosts_allowed = _builder.get(".properties.jumpHostsAllowed")
            if jump_hosts_allowed is not None:
                jump_hosts_allowed.set_elements(AAZStrType, ".")

            user_list = _builder.get(".properties.userList")
            if user_list is not None:
                user_list.set_elements(AAZObjectType, ".")

            _elements = _builder.get(".properties.userList[]")
            if _elements is not None:
                _elements.set_prop("azureUserName", AAZStrType, ".azure_user_name", typ_kwargs={"flags": {"required": True}})
                _elements.set_prop("description", AAZStrType, ".description")
                _elements.set_prop("sshPublicKey", AAZObjectType, ".ssh_public_key", typ_kwargs={"flags": {"required": True}})
                _elements.set_prop("userPrincipalName", AAZStrType, ".user_principal_name")

            ssh_public_key = _builder.get(".properties.userList[].sshPublicKey")
            if ssh_public_key is not None:
                ssh_public_key.set_prop("keyData", AAZStrType, ".key_data", typ_kwargs={"flags": {"required": True}})

            tags = _builder.get(".tags")
            if tags is not None:
                tags.set_elements(AAZStrType, ".")

            return self.serialize_content(_content_value)

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
            _UpdateHelper._build_schema_bare_metal_machine_key_set_read(cls._schema_on_200)

            return cls._schema_on_200


class _UpdateHelper:
    """Helper class for Update"""

    _schema_bare_metal_machine_key_set_read = None

    @classmethod
    def _build_schema_bare_metal_machine_key_set_read(cls, _schema):
        if cls._schema_bare_metal_machine_key_set_read is not None:
            _schema.extended_location = cls._schema_bare_metal_machine_key_set_read.extended_location
            _schema.id = cls._schema_bare_metal_machine_key_set_read.id
            _schema.location = cls._schema_bare_metal_machine_key_set_read.location
            _schema.name = cls._schema_bare_metal_machine_key_set_read.name
            _schema.properties = cls._schema_bare_metal_machine_key_set_read.properties
            _schema.system_data = cls._schema_bare_metal_machine_key_set_read.system_data
            _schema.tags = cls._schema_bare_metal_machine_key_set_read.tags
            _schema.type = cls._schema_bare_metal_machine_key_set_read.type
            return

        cls._schema_bare_metal_machine_key_set_read = _schema_bare_metal_machine_key_set_read = AAZObjectType()

        bare_metal_machine_key_set_read = _schema_bare_metal_machine_key_set_read
        bare_metal_machine_key_set_read.extended_location = AAZObjectType(
            serialized_name="extendedLocation",
            flags={"required": True},
        )
        bare_metal_machine_key_set_read.id = AAZStrType(
            flags={"read_only": True},
        )
        bare_metal_machine_key_set_read.location = AAZStrType(
            flags={"required": True},
        )
        bare_metal_machine_key_set_read.name = AAZStrType(
            flags={"read_only": True},
        )
        bare_metal_machine_key_set_read.properties = AAZObjectType(
            flags={"required": True, "client_flatten": True},
        )
        bare_metal_machine_key_set_read.system_data = AAZObjectType(
            serialized_name="systemData",
            flags={"read_only": True},
        )
        bare_metal_machine_key_set_read.tags = AAZDictType()
        bare_metal_machine_key_set_read.type = AAZStrType(
            flags={"read_only": True},
        )

        extended_location = _schema_bare_metal_machine_key_set_read.extended_location
        extended_location.name = AAZStrType(
            flags={"required": True},
        )
        extended_location.type = AAZStrType(
            flags={"required": True},
        )

        properties = _schema_bare_metal_machine_key_set_read.properties
        properties.azure_group_id = AAZStrType(
            serialized_name="azureGroupId",
            flags={"required": True},
        )
        properties.detailed_status = AAZStrType(
            serialized_name="detailedStatus",
            flags={"read_only": True},
        )
        properties.detailed_status_message = AAZStrType(
            serialized_name="detailedStatusMessage",
            flags={"read_only": True},
        )
        properties.expiration = AAZStrType(
            flags={"required": True},
        )
        properties.jump_hosts_allowed = AAZListType(
            serialized_name="jumpHostsAllowed",
            flags={"required": True},
        )
        properties.last_validation = AAZStrType(
            serialized_name="lastValidation",
            flags={"read_only": True},
        )
        properties.os_group_name = AAZStrType(
            serialized_name="osGroupName",
        )
        properties.privilege_level = AAZStrType(
            serialized_name="privilegeLevel",
            flags={"required": True},
        )
        properties.provisioning_state = AAZStrType(
            serialized_name="provisioningState",
            flags={"read_only": True},
        )
        properties.user_list = AAZListType(
            serialized_name="userList",
            flags={"required": True},
        )
        properties.user_list_status = AAZListType(
            serialized_name="userListStatus",
            flags={"read_only": True},
        )

        jump_hosts_allowed = _schema_bare_metal_machine_key_set_read.properties.jump_hosts_allowed
        jump_hosts_allowed.Element = AAZStrType()

        user_list = _schema_bare_metal_machine_key_set_read.properties.user_list
        user_list.Element = AAZObjectType()

        _element = _schema_bare_metal_machine_key_set_read.properties.user_list.Element
        _element.azure_user_name = AAZStrType(
            serialized_name="azureUserName",
            flags={"required": True},
        )
        _element.description = AAZStrType()
        _element.ssh_public_key = AAZObjectType(
            serialized_name="sshPublicKey",
            flags={"required": True},
        )
        _element.user_principal_name = AAZStrType(
            serialized_name="userPrincipalName",
        )

        ssh_public_key = _schema_bare_metal_machine_key_set_read.properties.user_list.Element.ssh_public_key
        ssh_public_key.key_data = AAZStrType(
            serialized_name="keyData",
            flags={"required": True},
        )

        user_list_status = _schema_bare_metal_machine_key_set_read.properties.user_list_status
        user_list_status.Element = AAZObjectType()

        _element = _schema_bare_metal_machine_key_set_read.properties.user_list_status.Element
        _element.azure_user_name = AAZStrType(
            serialized_name="azureUserName",
            flags={"read_only": True},
        )
        _element.status = AAZStrType(
            flags={"read_only": True},
        )
        _element.status_message = AAZStrType(
            serialized_name="statusMessage",
            flags={"read_only": True},
        )

        system_data = _schema_bare_metal_machine_key_set_read.system_data
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

        tags = _schema_bare_metal_machine_key_set_read.tags
        tags.Element = AAZStrType()

        _schema.extended_location = cls._schema_bare_metal_machine_key_set_read.extended_location
        _schema.id = cls._schema_bare_metal_machine_key_set_read.id
        _schema.location = cls._schema_bare_metal_machine_key_set_read.location
        _schema.name = cls._schema_bare_metal_machine_key_set_read.name
        _schema.properties = cls._schema_bare_metal_machine_key_set_read.properties
        _schema.system_data = cls._schema_bare_metal_machine_key_set_read.system_data
        _schema.tags = cls._schema_bare_metal_machine_key_set_read.tags
        _schema.type = cls._schema_bare_metal_machine_key_set_read.type


__all__ = ["Update"]
