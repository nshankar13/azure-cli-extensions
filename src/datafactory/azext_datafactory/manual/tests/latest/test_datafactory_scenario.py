# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from azure.cli.testsdk import ScenarioTest
from azure.cli.testsdk import ResourceGroupPreparer

# from knack.util import CLIError
from azure.cli.core.azclierror import AzCLIError, CLIInternalError, CLIError
import unittest

# Steps


def step_dataset_update(test, checks=None):
    if checks is None:
        checks = []
    test.cmd(
        "az datafactory dataset update "
        '--description "Example description" '
        '--linked-service-name "{{\\"type\\":\\"LinkedServiceReference\\",\\"referenceName\\":\\"{myLinkedService}'
        '\\"}}" '
        '--parameters "{{\\"MyFileName\\":{{\\"type\\":\\"String\\"}},\\"MyFolderPath\\":{{\\"type\\":\\"String\\"'
        '}}}}" '
        '--name "{myDataset}" '
        '--factory-name "{myFactory}" '
        '--resource-group "{rg}"',
        checks=checks,
    )


def step_linked_service_update(test, checks=None):
    if checks is None:
        checks = []
    test.cmd(
        "az datafactory linked-service update "
        '--factory-name "{myFactory}" '
        '--description "Example description" '
        '--name "{myLinkedService}" '
        '--resource-group "{rg}"',
        checks=checks,
    )


def step_trigger_update(test, checks=None):
    if checks is None:
        checks = []
    test.cmd(
        "az datafactory trigger update "
        '--factory-name "{myFactory}" '
        '--resource-group "{rg}" '
        '--description "Example description" '
        '--name "{myTrigger}"',
        checks=checks,
    )


# EXAMPLE: IntegrationRuntimes_Create
def step_integration_runtime_create(test):
    test.cmd(
        "az datafactory integration-runtime self-hosted create "
        '--factory-name "{myFactory}" '
        '--description "A selfhosted integration runtime" '
        '--name "{myIntegrationRuntime}" '
        '--resource-group "{rg}"',
        checks=[
            test.check("name", "{myIntegrationRuntime}"),
            test.check("properties.type", "SelfHosted"),
        ],
    )


def step_trigger_run_rerun(test):
    test.cmd(
        "az datafactory trigger-run rerun "
        '--factory-name "{myFactory}" '
        '--resource-group "{rg}" '
        '--trigger-name "{myTrigger}" '
        '--run-id "{myRunId}"',
        checks=[],
    )


def step_pipeline_create_run(test):
    output = test.cmd(
        "az datafactory pipeline create-run "
        '--factory-name "{myFactory}" '
        '--parameters "{{\\"OutputBlobNameList\\":[\\"exampleoutput.csv\\"]}}" '
        '--name "{myPipeline}" '
        '--resource-group "{rg}"',
        checks=[],
    ).get_output_in_json()
    return output


def step_pipeline_run_cancel(test):
    test.cmd(
        "az datafactory pipeline-run cancel "
        '--factory-name "{myFactory}" '
        '--resource-group "{rg}" '
        '--run-id "{myRunId}"',
        checks=[],
    )


def step_pipeline_run_show(test):
    test.cmd(
        "az datafactory pipeline-run show "
        '--factory-name "{myFactory}" '
        '--resource-group "{rg}" '
        '--run-id "{myRunId}"',
        checks=[],
    )


def step_pipeline_update(test):
    test.cmd(
        "az datafactory pipeline update "
        '--factory-name "{myFactory}" '
        '--description "Test Update description" '
        '--name "{myPipeline}" '
        '--resource-group "{rg}"',
        checks=[],
    )


def step_trigger_run_query_by_factory(test):
    output = test.cmd(
        "az datafactory trigger-run query-by-factory "
        '--factory-name "{myFactory}" '
        '--last-updated-after "{myStartTime}" '
        '--last-updated-before "{myEndTime}" '
        '--resource-group "{rg}"',
        checks=[],
    ).get_output_in_json()
    return output


def step_integration_runtime_managed_create(test):
    test.cmd(
        "az datafactory integration-runtime managed create "
        '--factory-name "{myFactory}" '
        '--name "{myIntegrationRuntime}" '
        '--resource-group "{rg}" '
        '--description "Managed Integration Runtime" '
        '--compute-properties "{{\\"location\\":'
        '\\"East US 2\\",\\"nodeSize\\":\\"Standard_D2_v3\\",'
        '\\"numberOfNodes\\":1,\\"maxParallelExecutionsPerNode\\":2}}" '
        '--ssis-properties "{{\\"edition\\":\\"Standard'
        '\\",\\"licenseType\\":\\"LicenseIncluded\\"}}" ',
        checks=[
            test.check("name", "{myIntegrationRuntime}"),
            test.check("properties.type", "Managed"),
        ],
    )


def step_pipeline_wait_create(test):
    test.cmd(
        "az datafactory pipeline create "
        '--factory-name "{myFactory}" '
        '--pipeline "{{\\"activities\\":[{{\\"name\\":\\"Wait1\\",'
        '\\"type\\":\\"Wait\\",\\"dependsOn\\":[],\\"userProperties'
        '\\":[],\\"typeProperties\\":{{\\"waitTimeInSeconds\\":5'
        '}}}}],\\"annotations\\":[]}}" '
        '--name "{myPipeline}" '
        '--resource-group "{rg}" ',
        checks=[
            test.check("name", "{myPipeline}"),
            test.check("activities[0].type", "Wait"),
        ],
    )


def step_trigger_tumble_create(test):
    test.cmd(
        "az datafactory trigger create "
        '--resource-group "{rg}" '
        '--properties "{{\\"description\\":\\"trumblingwindowtrigger'
        '\\",\\"annotations\\":[],\\"pipeline\\":{{\\"pipelineReference'
        '\\":{{\\"referenceName\\":\\"{myPipeline}\\",\\"type\\":'
        '\\"PipelineReference\\"}}}},\\"type\\":\\"TumblingWindowTrigger'
        '\\",\\"typeProperties\\":{{\\"frequency\\":\\"Minute\\",'
        '\\"interval\\":5,\\"startTime\\":\\"{myStartTime}\\",'
        '\\"endTime\\":\\"{myEndTime}\\",\\"delay\\":\\"00:00:00\\",'
        '\\"maxConcurrency\\":50,\\"retryPolicy\\":{{\\"intervalInSeconds'
        '\\":30}},\\"dependsOn\\":[]}}}}" '
        '--factory-name "{myFactory}" '
        '--name "{myTrigger}"',
        checks=[
            test.check("name", "{myTrigger}"),
            test.check("properties.type", "TumblingWindowTrigger"),
            test.check(
                "properties.pipeline.pipelineReference.referenceName", "{myPipeline}"
            ),
        ],
    )


def step_data_flow_create_mapping_data_flow(self):

    self.kwargs.update({"data_flow_type": "MappingDataFlow"})
    checks = [
        self.check("name", "{myMappingDataFlow}"),
        self.check("properties.type", "MappingDataFlow"),
        self.check("properties.description", "Example Text"),
    ]
    # Build command
    self.cmd(
        "az datafactory data-flow create "
        '--factory-name "{myFactory}" '
        '--resource-group "{rg}" '
        '--name "{myMappingDataFlow}" '
        '--flow-type "{data_flow_type}" '
        '--properties "{{\\"description\\": \\"Example Text\\"}}"',
        checks=checks,
    )


def step_data_flow_create_flowlet(self):
    self.kwargs.update({"data_flow_type": "Flowlet"})
    checks = [
        self.check("name", "{myFlowletDataFlow}"),
        self.check("properties.type", "Flowlet"),
        self.check("properties.description", "Example Text"),
    ]
    # Build command
    self.cmd(
        "az datafactory data-flow create "
        '--factory-name "{myFactory}" '
        '--resource-group "{rg}" '
        '--name "{myFlowletDataFlow}" '
        '--flow-type "{data_flow_type}" '
        '--properties "{{\\"description\\": \\"Example Text\\"}}"',
        checks=checks,
    )


def step_data_flow_delete(self):
    checks = []
    self.cmd(
        "az datafactory data-flow delete "
        '--factory-name "{myFactory}" '
        '--resource-group "{rg}" '
        '--name "{myMappingDataFlow}"',
        checks=checks,
    )


def step_data_flow_update(self):
    checks = [
        self.check("name", "{myMappingDataFlow}"),
        self.check("description", "A new example description"),
    ]
    self.cmd(
        "az datafactory data-flow update "
        '--factory-name "{myFactory}" '
        '--resource-group "{rg}" '
        '--name "{myMappingDataFlow}" '
        '--properties "{{\\"description\\": \\"A new example description\\"}}"',
        checks=checks,
    )


def step_data_flow_show(self):
    checks = [
        self.check("name", "{myMappingDataFlow}"),
        self.check("properties.type", "MappingDataFlow"),
        self.check("properties.description", "Example Text"),
        self.check("properties.annotations", []),
        self.check("properties.scriptLines", []),
        self.check("properties.sinks", []),
        self.check("properties.sources", []),
        self.check("properties.transformations", []),
        self.check("properties.folder", None),
        self.check("properties.script", None),
    ]
    self.cmd(
        "az datafactory data-flow show "
        '--factory-name "{myFactory}" '
        '--resource-group "{rg}" '
        '--name "{myMappingDataFlow}"',
        checks=checks,
    )


def step_data_flow_list(self):
    data_flow_list = self.cmd(
        "az datafactory data-flow list "
        '--factory-name "{myFactory}" '
        '--resource-group "{rg}"'
    ).get_output_in_json()
    self.assertTrue(len(data_flow_list) > 0)
    # Assume that at this point, two successful create commands
    self.assertTrue(len(data_flow_list) == 2)


# Scenarios


def call_managed_integrationruntime_scenario(test):
    from ....tests.latest import test_datafactory_scenario as g

    g.setup_main(test)
    g.step_create(test)
    step_integration_runtime_managed_create(test)
    g.step_integration_runtime_show(test)
    test.kwargs.update(
        {"myIntegrationRuntime2": test.kwargs.get("myIntegrationRuntime")}
    )
    g.step_integration_runtime_start(test)
    g.step_integration_runtime_stop(test)
    g.step_integration_runtime_delete(test)
    g.step_delete(test)
    g.cleanup_main(test)


def call_data_flow_scenario(test):
    from ....tests.latest import test_datafactory_scenario as g

    g.setup_main(test)
    g.step_create(test)
    step_data_flow_create_mapping_data_flow(test)
    step_data_flow_show(test)
    step_data_flow_create_flowlet(test)
    step_data_flow_list(test)
    step_data_flow_delete(test)
    g.step_delete(test)
    g.cleanup_main(test)


def call_triggerrun_scenario(test):
    from ....tests.latest import test_datafactory_scenario as g
    import time

    g.setup_main(test)
    g.step_create(test)
    step_pipeline_wait_create(test)
    createrun_res = step_pipeline_create_run(test)
    time.sleep(5)
    test.kwargs.update({"myRunId": createrun_res.get("runId")})
    step_pipeline_run_show(test)
    g.step_activity_run_query_by_pipeline_run(test)
    createrun_res = step_pipeline_create_run(test)
    test.kwargs.update({"myRunId": createrun_res.get("runId")})
    step_pipeline_run_cancel(test)
    step_trigger_tumble_create(test)
    g.step_trigger_start(test)
    g.step_trigger_show(test)
    maxRound = 2
    while True:
        triggerrun_res = step_trigger_run_query_by_factory(test)
        if (
            len(triggerrun_res["value"]) > 0
            and triggerrun_res["value"][0]["status"] == "Succeeded"
        ):
            test.kwargs.update({"myRunId": triggerrun_res["value"][0]["triggerRunId"]})
            break
        else:
            if maxRound > 0:
                maxRound -= 1
                print("waiting round: " + str(5 - maxRound))
                time.sleep(300)
            else:
                break
    if maxRound > 0:
        step_trigger_run_rerun(test)
    step_trigger_run_query_by_factory(test)
    g.step_trigger_stop(test)
    g.step_trigger_delete(test)
    g.step_pipeline_delete(test)
    g.step_delete(test)
    g.cleanup_main(test)


def call_main_scenario(test):
    from ....tests.latest import test_datafactory_scenario as g

    g.setup_main(test)
    g.step_create(test)
    g.step_update(test)
    g.step_linked_service_create(test)
    step_linked_service_update(test)
    g.step_dataset_create(test)
    step_dataset_update(test)
    g.step_pipeline_create(test)
    step_pipeline_update(test)
    g.step_trigger_create(test)
    step_trigger_update(test)
    g.step_integration_runtime_self_hosted_create(test)
    g.step_integration_runtime_update(test)
    # g.step_integration_runtime_linked(test)
    step_pipeline_create_run(test)
    g.step_integration_runtime_show(test)
    g.step_linked_service_show(test)
    g.step_pipeline_show(test)
    g.step_dataset_show(test)
    g.step_trigger_show(test)
    g.step_integration_runtime_list(test)
    g.step_linked_service_list(test)
    g.step_pipeline_list(test)
    g.step_trigger_list(test)
    g.step_dataset_list(test)
    g.step_show(test)
    g.step_list2(test)
    g.step_list(test)
    g.step_integration_runtime_regenerate_auth_key(test)
    # g.step_integration_runtime_get_connection_info(test)
    g.step_integration_runtime_sync_credentials(test)
    g.step_integration_runtime_get_monitoring_data(test)
    g.step_integration_runtime_list_auth_key(test)
    g.step_integration_runtime_remove_link(test)
    g.step_integration_runtime_get_status(test)
    # g.step_integration_runtime_start(test)
    # g.step_integration_runtime_stop(test)
    # g.step_integrationruntimes_createlinkedintegrationruntime(test)
    g.step_trigger_get_event_subscription_status(test)
    # g.step_activity_run_query_by_pipeline_run(test)
    g.step_trigger_unsubscribe_from_event(test)
    g.step_trigger_subscribe_to_event(test)
    g.step_trigger_start(test)
    g.step_trigger_stop(test)
    # g.step_get_git_hub_access_token(test)
    g.step_get_data_plane_access(test)
    # g.step_pipeline_run_query_by_factory(test)
    # g.step_pipeline_run_cancel(test)
    step_trigger_run_query_by_factory(test)
    g.step_configure_factory_repo(test)
    g.step_integration_runtime_delete(test)
    g.step_trigger_delete(test)
    g.step_pipeline_delete(test)
    g.step_dataset_delete(test)
    g.step_linked_service_delete(test)
    g.step_delete(test)
    g.cleanup_main(test)


def call_main(test):
    from datetime import datetime, timedelta

    now = datetime.utcnow()
    startTime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    an_hour_later = now + timedelta(hours=1)
    endTime = an_hour_later.strftime("%Y-%m-%dT%H:%M:%SZ")
    test.kwargs.update({"myStartTime": startTime, "myEndTime": endTime})
    call_main_scenario(test)
    call_data_flow_scenario(test)
    call_managed_integrationruntime_scenario(test)
    call_triggerrun_scenario(test)
