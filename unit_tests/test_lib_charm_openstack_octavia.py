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

from unittest import mock

import charms_openstack.test_utils as test_utils

import charm.openstack.octavia as octavia


class Helper(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.patch_release(octavia.RockyOctaviaCharm.release)


class TestOctaviaCharmConfigProperties(Helper):

    def test_health_manager_hwaddr(self):
        cls = mock.MagicMock()
        self.patch('json.loads', 'json_loads')
        self.patch('subprocess.check_output', 'check_output')
        self.check_output.side_effect = OSError
        self.check_output.return_value = '""'
        self.assertEqual(octavia.health_manager_hwaddr(cls), None)
        self.check_output.side_effect = None
        self.assertEqual(octavia.health_manager_hwaddr(cls), self.json_loads())
        self.json_loads.assert_called()
        self.check_output.assert_any_call(
            ['ovs-vsctl', 'get', 'Interface', octavia.OCTAVIA_MGMT_INTF,
             'external_ids:attached-mac'], universal_newlines=True)

    def test_health_manager_bind_ip(self):
        cls = mock.MagicMock()
        self.patch_object(octavia.ch_net_ip, 'get_iface_addr')
        data = ['fe80:db8:42%eth0', '2001:db8:42::42', '127.0.0.1']
        self.get_iface_addr.return_value = data
        self.assertEqual(octavia.health_manager_bind_ip(cls), data[1])
        self.get_iface_addr.assert_any_call(iface=octavia.OCTAVIA_MGMT_INTF,
                                            inet_type='AF_INET6')
        self.get_iface_addr.return_value = [data[2]]
        self.assertEqual(octavia.health_manager_bind_ip(cls), data[2])
        self.get_iface_addr.assert_any_call(iface=octavia.OCTAVIA_MGMT_INTF,
                                            inet_type='AF_INET6')

    def test_heartbeat_key(self):
        cls = mock.MagicMock()
        self.patch('charms.leadership.leader_get', 'leader_get')
        self.leader_get.return_value = None
        self.assertEqual(octavia.heartbeat_key(cls), None)
        self.leader_get.return_value = 'FAKE-STORED-UUID-STRING'
        self.assertEqual(octavia.heartbeat_key(cls), 'FAKE-STORED-UUID-STRING')
        self.leader_get.assert_called_with('heartbeat-key')

    def test_amp_flavor_id(self):
        cls = mock.MagicMock()
        self.patch('charmhelpers.core.hookenv.config', 'config')
        self.patch('charms.leadership.leader_get', 'leader_get')
        self.config.return_value = 'something'
        octavia.amp_flavor_id(cls)
        self.config.assert_called_with('custom-amp-flavor-id')
        self.assertFalse(self.leader_get.called)
        self.config.return_value = None
        octavia.amp_flavor_id(cls)
        self.leader_get.assert_called_with('amp-flavor-id')

    def test_controller_ip_port_list(self):
        cls = mock.MagicMock()
        self.patch('json.loads', 'json_loads')
        self.patch('charms.leadership.leader_get', 'leader_get')
        ip_list = ['2001:db8:42::42', '2001:db8:42::51']
        self.json_loads.return_value = ip_list
        self.assertEqual(
            octavia.controller_ip_port_list(cls),
            '2001:db8:42::42:{}, 2001:db8:42::51:{}'
            .format(octavia.OCTAVIA_HEALTH_LISTEN_PORT,
                    octavia.OCTAVIA_HEALTH_LISTEN_PORT))
        self.json_loads.assert_called_with(
            self.leader_get('controller-ip-port-list'))

    def test_amp_secgroup_list(self):
        cls = mock.MagicMock()
        self.patch('charms.leadership.leader_get', 'leader_get')
        octavia.amp_secgroup_list(cls)
        self.leader_get.assert_called_with('amp-secgroup-list')

    def test_amp_boot_network_list(self):
        cls = mock.MagicMock()
        self.patch('charms.leadership.leader_get', 'leader_get')
        octavia.amp_boot_network_list(cls)
        self.leader_get.assert_called_with('amp-boot-network-list')

    def test_spare_amphora_pool_size(self):
        cls = mock.MagicMock()
        self.patch('charmhelpers.core.hookenv.config', 'config')
        self.config.return_value = None
        self.assertEqual(octavia.spare_amphora_pool_size(cls), None)
        self.config.return_value = 5
        self.assertEqual(octavia.spare_amphora_pool_size(cls), 5)
        self.config.assert_called_with('spare-pool-size')


class TestOctaviaCharm(Helper):

    def setUp(self):
        super().setUp()
        self.patch_object(octavia.reactive, 'is_flag_set', return_value=False)
        self.target = octavia.RockyOctaviaCharm()
        # remove the 'is_flag_set' patch so the tests can use it
        self._patches['is_flag_set'].stop()
        setattr(self, 'is_flag_set', None)
        del self._patches['is_flag_set']
        del self._patches_start['is_flag_set']

    def test_optional_ovn_provider_driver(self):
        self.assertFalse('octavia-driver-agent' in self.target.packages)
        self.assertFalse(
            'python3-ovn-octavia-provider' in self.target.packages)
        self.patch_object(octavia.reactive, 'is_flag_set', return_value=True)
        c = octavia.VictoriaOctaviaCharm()
        self.assertTrue('octavia-driver-agent' in c.all_packages)
        self.assertTrue('python3-ovn-octavia-provider' in c.all_packages)
        self.assertTrue('octavia-driver-agent' in c.full_service_list)

    def test_install(self):
        # we do not care about the internals of the function we are overriding
        # and expanding so mock out the call to super()
        self.patch('builtins.super', 'super')
        self.patch_object(octavia.ch_core, 'host')
        self.target.install()
        self.super.assert_called()
        self.host.add_user_to_group.assert_called_once_with('systemd-network',
                                                            'octavia')
        self.host.service_pause.assert_called_once_with('octavia-api')

    # NOTE(fnordahl): for some reason our patch helper blows up on Python 3.6
    # when patching this function, so let's resort to the good ol' decorator
    # for this mock.
    @mock.patch('charms_openstack.adapters.make_default_options')
    def test_states_to_check(self, options):
        # we do not care about the internals of the function we are overriding
        # and expanding so mock out the call to super()
        self.patch('builtins.super', 'super')
        self.patch_object(octavia.leadership, 'leader_get')
        self.patch_object(octavia.reactive, 'is_flag_set')
        self.leader_get.return_value = True
        self.is_flag_set.return_value = True
        override_relation = 'neutron-openvswitch'
        states_to_check = {
            override_relation: 'something-we-are-replacing',
        }
        self.super().states_to_check.return_value = states_to_check
        options().enable_amphora = False
        self.target.states_to_check()
        self.super().states_to_check.assert_called_once_with(None)
        self.assertFalse(self.leader_get.called)
        options().enable_amphora = True
        self.target.states_to_check()
        self.leader_get.assert_called_once_with(
            'amp-boot-network-list')
        self.is_flag_set.assert_has_calls([
            mock.call('config.default.lb-mgmt-issuing-cacert')])
        self.super.assert_called()

    def test_get_amqp_credentials(self):
        result = self.target.get_amqp_credentials()
        self.assertEqual(result, ('octavia', 'openstack'))

    def test_get_database_setup(self):
        result = self.target.get_database_setup()
        self.assertEqual(result, [{'database': 'octavia',
                                   'username': 'octavia'}])

    def test_enable_webserver_site(self):
        self.patch('os.path.exists', 'exists')
        self.patch('subprocess.call', 'sp_call')
        self.patch('subprocess.check_call', 'sp_check_call')
        self.patch('charmhelpers.core.host.service_reload', 'service_reload')
        self.exists.return_value = True
        self.sp_call.return_value = True
        self.target.enable_webserver_site()
        self.exists.assert_called_with(
            '/etc/apache2/sites-available/octavia-api.conf')
        self.sp_call.assert_called_with(['a2query', '-s', 'octavia-api'])
        self.sp_check_call.assert_called_with(['a2ensite', 'octavia-api'])
        self.service_reload.assert_called_with(
            'apache2', restart_on_failure=True)

    def test_local_address(self):
        configuration_class = mock.MagicMock()
        self.target.configuration_class = configuration_class
        self.assertEqual(self.target.local_address,
                         configuration_class().local_address)

    def test_local_unit_name(self):
        configuration_class = mock.MagicMock()
        self.target.configuration_class = configuration_class
        self.assertEqual(self.target.local_unit_name,
                         configuration_class().local_unit_name)
