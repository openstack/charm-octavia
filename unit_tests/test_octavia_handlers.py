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

import json
import mock

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
                    'amqp.available',),
                'update_controller_ip_port_list': (
                    'leadership.is_leader',
                    'identity-service.available',
                    'neutron-api.available',
                    'amqp.available',),
                'setup_endpoint_connection': (
                    'identity-service.connected',),
            },
            'when_any': {
                'sdn_joined': ('neutron-openvswitch.connected',
                               'ovsdb-subordinate.available'),
            },
            'when_none': {
                'sdn_broken': ('neutron-openvswitch.connected',
                               'ovsdb-subordinate.available'),
            },
            'when_not': {
                'init_db': ('db.synced',),
                'cluster_connected': ('ha.available',),
                'generate_heartbeat_key': ('leadership.set.heartbeat-key',),
            },
        }
        # test that the hooks were registered via the
        # reactive.octavia_handlers
        self.registered_hooks_test_helper(handlers, hook_set, defaults)


class TestOctaviaHandlers(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.patch_release(octavia.OctaviaCharm.release)
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
            requested_roles=octavia.OCTAVIA_ROLES)
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
        handlers.setup_hm_port()
        self.setup_hm_port.assert_called_with(
            self.endpoint_from_flag(),
            self.octavia_charm,
            host_id=self.endpoint_from_flag().host())
        self.set_flag.assert_called_once_with('config.changed')
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
        self.patch_object(handlers.api_crud, 'get_port_ips')
        self.get_port_ips.return_value = [
            '2001:db8:42::42',
            '2001:db8:42::51',
        ]
        handlers.update_controller_ip_port_list()
        self.leader_set.assert_called_once_with(
            {
                'controller-ip-port-list': json.dumps([
                    '2001:db8:42::42',
                    '2001:db8:42::51',
                ])})

    def test_render(self):
        self.patch('charms.reactive.set_state', 'set_state')
        self.patch_object(handlers.api_crud, 'create_nova_keypair')
        handlers.render('arg1', 'arg2')
        self.octavia_charm.render_with_interfaces.assert_called_once_with(
            ('arg1', 'arg2'))
        self.octavia_charm.configure_ssl.assert_called_once_with()
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
