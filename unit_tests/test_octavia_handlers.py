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

import json
from unittest import mock

import charm.openstack.octavia as octavia
import reactive.octavia_handlers as handlers

import charms_openstack.test_utils as test_utils


class TestRegisteredHooks(test_utils.TestRegisteredHooks):

    def test_hooks(self):
        defaults = [
            'charm.installed',
            'amqp.connected',
            'shared-db.connected',
            'identity-service.connected',
            'config.changed',
            'update-status',
            'upgrade-charm',
            'certificates.available',
        ]
        hook_set = {
            'when': {
                'ensure_hm_port_mtu': ('is-update-status-hook',
                                       'octavia.hm-port.available'),
                'render': ('shared-db.available',
                           'identity-service.available',
                           'amqp.available',
                           'leadership.set.heartbeat-key',),
                'init_db': ('config.rendered',),
                'cluster_connected': ('ha.connected',),
                'generate_heartbeat_key': ('leadership.is_leader',),
                'setup_neutron_lbaas_proxy': (
                    'neutron-api.available',),
                'setup_hm_port': (
                    'identity-service.available',
                    'neutron-api.available',
                    'sdn-subordinate.available',
                    'amqp.available',
                    'config.default.enable-amphora',
                ),
                'update_controller_ip_port_list': (
                    'leadership.is_leader',
                    'identity-service.available',
                    'neutron-api.available',
                    'amqp.available',
                    'config.default.enable-amphora',
                ),
                'setup_endpoint_connection': (
                    'identity-service.connected',),
                'maybe_enable_ovn_driver': (
                    'ovsdb-subordinate.available',),
                'update_nagios': (
                    'charm.installed',
                    'nrpe-external-master.available',),
                'action_setup_hm_port': (
                    'config.default.enable-amphora',
                    'charm.octavia.action_setup_hm_port',),
            },
            'when_any': {
                'sdn_joined': ('neutron-openvswitch.connected',
                               'ovsdb-subordinate.available'),
                'nagios_config_changed': (
                    'config.changed.nagios_context',
                    'config.changed.nagios_servicegroups'),
            },
            'when_none': {
                'sdn_broken': ('neutron-openvswitch.connected',
                               'ovsdb-subordinate.available'),
            },
            'when_not': {
                'init_db': ('db.synced', 'is-update-status-hook'),
                'cluster_connected': ('ha.available', 'is-update-status-hook'),
                'generate_heartbeat_key': ('leadership.set.heartbeat-key',
                                           'is-update-status-hook'),
                'disable_ovn_driver': ('ovsdb-subordinate.available',),
                'maybe_enable_ovn_driver': ('is-update-status-hook',),
                'setup_endpoint_connection': ('is-update-status-hook',),
                'setup_neutron_lbaas_proxy': ('is-update-status-hook',),
                'setup_hm_port': ('is-update-status-hook',
                                  'unit.is.departing',),
                'update_controller_ip_port_list': ('is-update-status-hook',),
                'render': ('is-update-status-hook',),
                'update_nagios': ('octavia.nrpe.configured',
                                  'is-update-status-hook'),
            },
            'hook': {
                'upgrade_charm': ('upgrade-charm',),
            },
        }
        # test that the hooks were registered via the
        # reactive.octavia_handlers
        self.registered_hooks_test_helper(handlers, hook_set, defaults)


class TestOctaviaHandlers(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.patch_release(octavia.RockyOctaviaCharm.release)
        self.octavia_charm = mock.MagicMock()
        self.patch_object(handlers.charm, 'provide_charm_instance',
                          new=mock.MagicMock())
        self.provide_charm_instance().__enter__.return_value = \
            self.octavia_charm
        self.provide_charm_instance().__exit__.return_value = None

    def test_setup_endpoint_connection(self):
        keystone = mock.MagicMock()
        handlers.setup_endpoint_connection(keystone)
        keystone.register_endpoints.assert_called_once_with(
            self.octavia_charm.service_type,
            self.octavia_charm.region,
            self.octavia_charm.public_url,
            self.octavia_charm.internal_url,
            self.octavia_charm.admin_url,
            requested_roles=octavia.OCTAVIA_ROLES,
            add_role_to_admin=octavia.OCTAVIA_ROLES)
        self.octavia_charm.assess_status.assert_called_once_with()

    def test_generate_heartbeat_key(self):
        self.patch('charms.leadership.leader_set', 'leader_set')
        self.patch('uuid.uuid4', 'uuid4')
        self.uuid4.return_value = fake_uuid4 = 'FAKE-UUID4-STRING'
        handlers.generate_heartbeat_key()
        self.leader_set.assert_called_once_with(
            {'heartbeat-key': fake_uuid4})
        self.uuid4.assert_called_once_with()

    def test_neutron_lbaas_proxy(self):
        self.patch('charms.reactive.endpoint_from_flag', 'endpoint_from_flag')
        endpoint = mock.MagicMock()
        self.endpoint_from_flag.return_value = endpoint
        self.patch('charms_openstack.ip.canonical_url', 'canonical_url')
        self.canonical_url.return_value = 'http://1.2.3.4'
        self.octavia_charm.api_port.return_value = '1234'
        handlers.setup_neutron_lbaas_proxy()
        self.canonical_url.assert_called_with(endpoint_type='int')
        endpoint.publish_load_balancer_info.assert_called_with(
            'octavia', 'http://1.2.3.4:1234')

    def test_setup_hm_port(self):
        self.patch('charms.reactive.endpoint_from_flag', 'endpoint_from_flag')
        self.patch('charms.reactive.set_flag', 'set_flag')
        self.patch_object(handlers.api_crud, 'setup_hm_port')
        self.patch_object(handlers.api_crud, 'wait_for_hm_port_bound')
        self.wait_for_hm_port_bound = True
        handlers.setup_hm_port()
        self.setup_hm_port.assert_called_with(
            self.endpoint_from_flag(),
            self.octavia_charm,
            host_id=self.endpoint_from_flag().host())
        self.set_flag.assert_has_calls([
            mock.call('config.changed'),
            mock.call('octavia.hm-port.available')])
        self.setup_hm_port.reset_mock()
        ovsdb_subordinate = mock.MagicMock()
        identity_service = mock.MagicMock()
        self.endpoint_from_flag.side_effect = [
            None, ovsdb_subordinate, identity_service]
        handlers.setup_hm_port()
        self.setup_hm_port.assert_called_with(
            identity_service,
            self.octavia_charm,
            host_id=ovsdb_subordinate.chassis_name)

    def test_update_controller_ip_port_list(self):
        self.patch('charms.reactive.endpoint_from_flag', 'endpoint_from_flag')
        self.patch('charms.leadership.leader_set', 'leader_set')
        self.patch('charms.leadership.leader_get', 'leader_get')
        self.patch_object(handlers.api_crud, 'get_port_ip_unit_map')
        fake_ip_unit_map = {'lb-0': '2001:db8:42::1', 'lb-1': '2001:db8:42::2'}
        self.get_port_ip_unit_map.return_value = fake_ip_unit_map
        self.patch_object(handlers.ch_core.hookenv, 'departing_unit')
        self.departing_unit.return_value = 'lb/1'
        self.patch_object(handlers.api_crud, 'delete_hm_port')
        handlers.update_controller_ip_port_list()
        self.leader_set.assert_called_once_with(
            {
                'controller-ip-port-list': json.dumps([
                    '2001:db8:42::1',
                ])})

    def test_render(self):
        self.patch('charms.reactive.set_state', 'set_state')
        self.patch_object(handlers.api_crud, 'create_nova_keypair')
        self.patch_object(handlers.charm, 'optional_interfaces')
        self.optional_interfaces.return_value = ('fake', 'interface', 'list')
        handlers.render('arg1', 'arg2')
        self.octavia_charm.render_with_interfaces.assert_called_once_with(
            ('fake', 'interface', 'list'))
        self.optional_interfaces.assert_called_once_with(
            ('arg1', 'arg2'), 'ovsdb-subordinate.available',
            'ovsdb-cms.available')
        self.octavia_charm.configure_ssl.assert_called_once_with()
        self.octavia_charm.upgrade_if_available.assert_called_once_with(
            ('arg1', 'arg2'))
        self.octavia_charm.enable_webserver_site.assert_called_once_with()
        self.octavia_charm.assess_status.assert_called_once_with()
        self.set_state.assert_called_once_with('config.rendered')

    def test_init_db(self):
        self.patch('charms.reactive.set_state', 'set_state')
        handlers.init_db()
        self.octavia_charm.db_sync.assert_called_once_with()
        self.octavia_charm.restart_all.assert_called_once_with()
        self.set_state.assert_called_once_with('db.synced')
        self.octavia_charm.assess_status.assert_called_once_with()

    def test_cluster_connected(self):
        hacluster = mock.MagicMock()
        handlers.cluster_connected(hacluster)
        self.octavia_charm.configure_ha_resources.assert_called_once_with(
            hacluster)
        self.octavia_charm.assess_status.assert_called_once_with()

    def test_disable_ovn_driver(self):
        self.patch_object(octavia.reactive, 'clear_flag')
        handlers.disable_ovn_driver()
        self.clear_flag.assert_called_once_with(
            'charm.octavia.enable-ovn-driver')

    def test_maybe_enable_ovn_driver(self):
        ovsdb = mock.MagicMock()
        ovsdb.ovn_configured = True
        self.patch_object(octavia.reactive, 'endpoint_from_flag')
        self.endpoint_from_flag.return_value = ovsdb
        self.patch_object(octavia.reactive, 'set_flag')
        handlers.maybe_enable_ovn_driver()
        self.endpoint_from_flag.assert_called_once_with(
            'ovsdb-subordinate.available')
        self.set_flag.assert_called_once_with(
            'charm.octavia.enable-ovn-driver')
        self.octavia_charm.install.assert_called_once_with()
        self.octavia_charm.assess_status.assert_called_once_with()

    def test_update_nagios(self):
        self.patch_object(handlers.nrpe, 'get_nagios_unit_name',
                          return_value=mock.sentinel.unit_name)
        nrpe_instance = mock.MagicMock()
        self.patch_object(handlers.nrpe, 'NRPE', return_value=nrpe_instance)
        self.patch_object(handlers.nrpe, 'add_init_service_checks')
        self.patch_object(handlers.nrpe, 'copy_nrpe_checks')
        self.patch('charms.reactive.set_state')
        handlers.update_nagios()
        self.add_init_service_checks.assert_called_once_with(
            nrpe_instance, self.octavia_charm.full_service_list,
            mock.sentinel.unit_name)
        self.copy_nrpe_checks.assert_called_once_with(
            nrpe_files_dir="./files/nrpe")
        nrpe_instance.write.assert_called_once()
        self.set_state.assert_called_once_with('octavia.nrpe.configured')

    def test_nagios_config_changed(self):
        self.patch('charms.reactive.remove_state')
        handlers.nagios_config_changed()
        self.remove_state.assert_any_call('octavia.nrpe.configured')
        self.remove_state.assert_any_call('config.changed.nagios_context')
        self.remove_state.assert_any_call(
            'config.changed.nagios_servicegroups')
        self.assertEqual(self.remove_state.call_count, 3)
