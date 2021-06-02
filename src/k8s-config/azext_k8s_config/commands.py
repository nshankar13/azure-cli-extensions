# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# pylint: disable=line-too-long
from azure.cli.core.commands import CliCommandType
from azext_k8s_config._client_factory import k8s_config_fluxconfig_client


def load_command_table(self, _):
    k8s_config_fluxconfig_sdk = CliCommandType(
        operations_tmpl='azext_k8s_config.vendored_sdks.operations#FluxConfigurationsOperations.{}',
        client_factory=k8s_config_fluxconfig_client
    )

    with self.command_group('k8s-config flux', k8s_config_fluxconfig_sdk, client_factory=k8s_config_fluxconfig_client, is_preview=True) as g:
        g.custom_command('create', 'flux_config_create')
        g.command('list', "list")
        g.custom_command('show', 'flux_config_show')
        g.custom_command('delete', 'flux_config_delete', confirmation=True)