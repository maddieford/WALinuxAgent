# Copyright 2020 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.6+ and Openssl 1.0+
#

import os
import tempfile
import unittest

import azurelinuxagent.common.protocol.metadata_server_migration_util as migration_util

from azurelinuxagent.common.protocol.metadata_server_migration_util import _LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME, \
                                                                           _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME, \
                                                                           _LEGACY_METADATA_SERVER_P7B_FILE_NAME
from tests.lib.tools import AgentTestCase, patch

class TestMetadataServerMigrationUtil(AgentTestCase):
    @patch('azurelinuxagent.common.conf.get_lib_dir')
    def test_is_metadata_server_artifact_present(self, mock_get_lib_dir):
        dir = tempfile.gettempdir()  # pylint: disable=redefined-builtin
        metadata_server_transport_cert_file = os.path.join(dir, _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME)
        open(metadata_server_transport_cert_file, 'w').close()
        mock_get_lib_dir.return_value = dir
        self.assertTrue(migration_util.is_metadata_server_artifact_present())

    @patch('azurelinuxagent.common.conf.get_lib_dir')
    def test_is_metadata_server_artifact_not_present(self, mock_get_lib_dir):
        mock_get_lib_dir.return_value = tempfile.gettempdir()
        self.assertFalse(migration_util.is_metadata_server_artifact_present())

    @patch('azurelinuxagent.common.conf.enable_firewall')
    @patch('azurelinuxagent.common.conf.get_lib_dir')
    def test_cleanup_metadata_server_artifacts_does_not_throw_with_no_metadata_certs(self, mock_get_lib_dir, mock_enable_firewall):
        mock_get_lib_dir.return_value = tempfile.gettempdir()
        mock_enable_firewall.return_value = False
        migration_util.cleanup_metadata_server_artifacts()

    @patch('azurelinuxagent.common.conf.enable_firewall')
    @patch('azurelinuxagent.common.conf.get_lib_dir')
    @patch('os.getuid')
    @patch("azurelinuxagent.common.protocol.metadata_server_migration_util._get_firewall_will_wait", return_value="-w")
    def test_cleanup_metadata_server_artifacts_firewall_enabled(self, _, mock_os_getuid, mock_get_lib_dir, mock_enable_firewall):
        # Setup Certificate Files
        dir = tempfile.gettempdir()  # pylint: disable=redefined-builtin
        metadata_server_transport_prv_file = os.path.join(dir, _LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME)
        metadata_server_transport_cert_file = os.path.join(dir, _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME)
        metadata_server_p7b_file = os.path.join(dir, _LEGACY_METADATA_SERVER_P7B_FILE_NAME)
        open(metadata_server_transport_prv_file, 'w').close()
        open(metadata_server_transport_cert_file, 'w').close()
        open(metadata_server_p7b_file, 'w').close()

        # Setup Mocks
        mock_get_lib_dir.return_value = dir
        mock_enable_firewall.return_value = True
        fixed_uid = 0
        mock_os_getuid.return_value = fixed_uid

        # Run
        with patch("azurelinuxagent.common.protocol.metadata_server_migration_util._remove_firewall") as mock_remove_firewall:
            migration_util.cleanup_metadata_server_artifacts()

        # Assert files deleted
        self.assertFalse(os.path.exists(metadata_server_transport_prv_file))
        self.assertFalse(os.path.exists(metadata_server_transport_cert_file))
        self.assertFalse(os.path.exists(metadata_server_p7b_file))

        # Assert Firewall rule calls
        self.assertEqual(1, mock_remove_firewall.call_count, "_remove_firewall should be called once")

    @patch('azurelinuxagent.common.conf.enable_firewall')
    @patch('azurelinuxagent.common.conf.get_lib_dir')
    @patch('os.getuid')
    @patch("azurelinuxagent.common.protocol.metadata_server_migration_util._get_firewall_will_wait", return_value="-w")
    def test_cleanup_metadata_server_artifacts_firewall_disabled(self, _, mock_os_getuid, mock_get_lib_dir, mock_enable_firewall):
        # Setup Certificate Files
        dir = tempfile.gettempdir()  # pylint: disable=redefined-builtin
        metadata_server_transport_prv_file = os.path.join(dir, _LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME)
        metadata_server_transport_cert_file = os.path.join(dir, _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME)
        metadata_server_p7b_file = os.path.join(dir, _LEGACY_METADATA_SERVER_P7B_FILE_NAME)
        open(metadata_server_transport_prv_file, 'w').close()
        open(metadata_server_transport_cert_file, 'w').close()
        open(metadata_server_p7b_file, 'w').close()

        # Setup Mocks
        mock_get_lib_dir.return_value = dir
        mock_enable_firewall.return_value = False
        fixed_uid = 0
        mock_os_getuid.return_value = fixed_uid

        # Run
        with patch("azurelinuxagent.common.protocol.metadata_server_migration_util._remove_firewall") as mock_remove_firewall:
            migration_util.cleanup_metadata_server_artifacts()

        # Assert files deleted
        self.assertFalse(os.path.exists(metadata_server_transport_prv_file))
        self.assertFalse(os.path.exists(metadata_server_transport_cert_file))
        self.assertFalse(os.path.exists(metadata_server_p7b_file))

        # Assert Firewall rule calls
        self.assertEqual(1, mock_remove_firewall.call_count, "_remove_firewall should be called once")

    # Cleanup certificate files
    def tearDown(self):
        # pylint: disable=redefined-builtin
        dir = tempfile.gettempdir()
        for file in [_LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME, \
                     _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME, \
                     _LEGACY_METADATA_SERVER_P7B_FILE_NAME]:
            path = os.path.join(dir, file)
            if os.path.exists(path):
                os.remove(path)
        # pylint: enable=redefined-builtin

        super(TestMetadataServerMigrationUtil, self).tearDown()

if __name__ == '__main__':
    unittest.main()
