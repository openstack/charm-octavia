# Copyright 2018 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import
from __future__ import print_function

import charms_openstack.test_utils as test_utils

import charm.openstack.octavia as octavia


class Helper(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.patch_release(octavia.OctaviaCharm.release)


class TestOctaviaCharm(Helper):

    def test_get_amqp_credentials(self):
        c = octavia.OctaviaCharm()
        result = c.get_amqp_credentials()
        self.assertEqual(result, ('octavia', 'openstack'))

    def test_get_database_setup(self):
        c = octavia.OctaviaCharm()
        result = c.get_database_setup()
        self.assertEqual(result, [{'database': 'octavia',
                                   'username': 'octavia'}])

    def test_enable_webserver_site(self):
        self.patch('os.path.exists', 'exists')
        self.patch('subprocess.call', 'sp_call')
        self.patch('subprocess.check_call', 'sp_check_call')
        self.patch('charmhelpers.core.host.service_reload', 'service_reload')
        self.exists.return_value = True
        self.sp_call.return_value = True
        c = octavia.OctaviaCharm()
        c.enable_webserver_site()
        self.exists.assert_called_with(
            '/etc/apache2/sites-available/octavia-api.conf')
        self.sp_call.assert_called_with(['a2query', '-s', 'octavia-api'])
        self.sp_check_call.assert_called_with(['a2ensite', 'octavia-api'])
        self.service_reload.assert_called_with(
            'apache2', restart_on_failure=True)
