# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import base64
from azure.cli.core.azclierror import InvalidArgumentValueError, \
    RequiredArgumentMissingError, MutuallyExclusiveArgumentError

from ._validators import _validate_private_key


def _get_protected_settings(ssh_private_key, ssh_private_key_file, https_user, https_key):
    protected_settings = {}
    ssh_private_key_data = _get_data_from_key_or_file(ssh_private_key, ssh_private_key_file)

    # Add gitops private key data to protected settings if exists
    # Dry-run all key types to determine if the private key is in a valid format
    if ssh_private_key_data != '':
        _validate_private_key(ssh_private_key_data)
        protected_settings["sshPrivateKey"] = ssh_private_key_data

    # Check if both httpsUser and httpsKey exist, then add to protected settings
    if https_user != '' and https_key != '':
        protected_settings['httpsUser'] = _to_base64(https_user)
        protected_settings['httpsKey'] = _to_base64(https_key)
    elif https_user != '':
        raise RequiredArgumentMissingError(
            'Error! --https-user used without --https-key',
            'Try providing both --https-user and --https-key together')
    elif https_key != '':
        raise RequiredArgumentMissingError(
            'Error! --http-key used without --http-user',
            'Try providing both --https-user and --https-key together')

    return protected_settings


def _get_cluster_type(cluster_type):
    if cluster_type.lower() == 'connectedclusters':
        return 'Microsoft.Kubernetes'
    # Since cluster_type is an enum of only two values, if not connectedClusters, it will be managedClusters.
    return 'Microsoft.ContainerService'


def _fix_compliance_state(config):
    # If we get Compliant/NonCompliant as compliance_sate, change them before returning
    if config.compliance_status.compliance_state.lower() == 'noncompliant':
        config.compliance_status.compliance_state = 'Failed'
    elif config.compliance_status.compliance_state.lower() == 'compliant':
        config.compliance_status.compliance_state = 'Installed'

    return config


def _get_data_from_key_or_file(key, filepath):
    if key != '' and filepath != '':
        raise MutuallyExclusiveArgumentError(
            'Error! Both textual key and key filepath cannot be provided',
            'Try providing the file parameter without providing the plaintext parameter')
    data = ''
    if filepath != '':
        data = _read_key_file(filepath)
    elif key != '':
        data = key
    return data


def _read_key_file(path):
    try:
        with open(path, "r") as myfile:  # user passed in filename
            data_list = myfile.readlines()  # keeps newline characters intact
            data_list_len = len(data_list)
            if (data_list_len) <= 0:
                raise Exception("File provided does not contain any data")
            raw_data = ''.join(data_list)
        return _to_base64(raw_data)
    except Exception as ex:
        raise InvalidArgumentValueError(
            'Error! Unable to read key file specified with: {0}'.format(ex),
            'Verify that the filepath specified exists and contains valid utf-8 data') from ex


def _from_base64(base64_str):
    return base64.b64decode(base64_str)


def _to_base64(raw_data):
    bytes_data = raw_data.encode('utf-8')
    return base64.b64encode(bytes_data).decode('utf-8')
