# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core import AzCommandsLoader

from azext_blueprint._help import helps  # pylint: disable=unused-import


class BlueprintCommandsLoader(AzCommandsLoader):

    def __init__(self, cli_ctx=None):
        from azure.cli.core.commands import CliCommandType
        from azext_blueprint._client_factory import cf_blueprint
        blueprint_custom = CliCommandType(
            operations_tmpl='azext_blueprint.custom#{}',
            client_factory=cf_blueprint)
        super().__init__(cli_ctx=cli_ctx,
                         custom_command_type=blueprint_custom)

    def load_command_table(self, args):
        from azext_blueprint.commands import load_command_table
        from azure.cli.core.aaz import load_aaz_command_table
        try:
            from . import aaz
        except ImportError:
            aaz = None
        if aaz:
            load_aaz_command_table(
                loader=self,
                aaz_pkg_name=aaz.__name__,
                args=args
            )
        load_command_table(self, args)
        return self.command_table

    def load_arguments(self, command):
        from azext_blueprint._params import load_arguments
        load_arguments(self, command)


COMMAND_LOADER_CLS = BlueprintCommandsLoader
