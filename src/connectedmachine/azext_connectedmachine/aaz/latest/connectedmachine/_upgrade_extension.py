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
    "connectedmachine upgrade-extension",
)
class UpgradeExtension(AAZCommand):
    """The operation to upgrade Machine Extensions.

    :example: Sample command for extension upgrade
        az connectedmachine extension upgrade --machine-name "myMachineName" --resource-group "myResourceGroup" --subscription "mySubscription" --targets "{"Microsoft.Compute.CustomScriptExtension": "{"targetVersion": "1.10"}", "Microsoft.Azure.Monitoring": "{"targetVersion": "2.0"}"}"
    """

    _aaz_info = {
        "version": "2023-10-03-preview",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.hybridcompute/machines/{}/upgradeextensions", "2023-10-03-preview"],
        ]
    }

    AZ_SUPPORT_NO_WAIT = True

    def _handler(self, command_args):
        super()._handler(command_args)
        return self.build_lro_poller(self._execute_operations, None)

    _args_schema = None

    @classmethod
    def _build_arguments_schema(cls, *args, **kwargs):
        if cls._args_schema is not None:
            return cls._args_schema
        cls._args_schema = super()._build_arguments_schema(*args, **kwargs)

        # define Arg Group ""

        _args_schema = cls._args_schema
        _args_schema.machine_name = AAZStrArg(
            options=["--machine-name"],
            help="The name of the hybrid machine.",
            required=True,
            id_part="name",
            fmt=AAZStrArgFormat(
                pattern="^[a-zA-Z0-9-_\.]{1,54}$",
                max_length=54,
                min_length=1,
            ),
        )
        _args_schema.resource_group = AAZResourceGroupNameArg(
            required=True,
        )

        # define Arg Group "ExtensionUpgradeParameters"

        _args_schema = cls._args_schema
        _args_schema.extension_targets = AAZDictArg(
            options=["--extension-targets"],
            arg_group="ExtensionUpgradeParameters",
            help="Describes the Extension Target Properties.",
        )

        extension_targets = cls._args_schema.extension_targets
        extension_targets.Element = AAZObjectArg()

        _element = cls._args_schema.extension_targets.Element
        _element.target_version = AAZStrArg(
            options=["target-version"],
            help="Properties for the specified Extension to Upgrade.",
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        yield self.UpgradeExtensions(ctx=self.ctx)()
        self.post_operations()

    @register_callback
    def pre_operations(self):
        pass

    @register_callback
    def post_operations(self):
        pass

    class UpgradeExtensions(AAZHttpOperation):
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
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.HybridCompute/machines/{machineName}/upgradeExtensions",
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
                    "machineName", self.ctx.args.machine_name,
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
                    "api-version", "2023-10-03-preview",
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
            }
            return parameters

        @property
        def content(self):
            _content_value, _builder = self.new_content_builder(
                self.ctx.args,
                typ=AAZObjectType,
                typ_kwargs={"flags": {"required": True, "client_flatten": True}}
            )
            _builder.set_prop("extensionTargets", AAZDictType, ".extension_targets")

            extension_targets = _builder.get(".extensionTargets")
            if extension_targets is not None:
                extension_targets.set_elements(AAZObjectType, ".")

            _elements = _builder.get(".extensionTargets{}")
            if _elements is not None:
                _elements.set_prop("targetVersion", AAZStrType, ".target_version")

            return self.serialize_content(_content_value)

        def on_200(self, session):
            pass


class _UpgradeExtensionHelper:
    """Helper class for UpgradeExtension"""


__all__ = ["UpgradeExtension"]
