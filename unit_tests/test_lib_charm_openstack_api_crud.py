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

import contextlib
from unittest import mock
import subprocess

import charms_openstack.test_utils as test_utils

import charm.openstack.octavia as octavia  # for constants
import charm.openstack.api_crud as api_crud

from openstack import connection


class FakeNeutronConflictException(Exception):
    pass


class TestAPICrud(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.secgrp_uuid = 'fake-secgrp-uuid'
        self.health_secgrp_uuid = 'fake-health_secgrp-uuid'
        self.security_group_rule_calls = [
            mock.call(**{
                'direction': 'ingress',
                'protocol': 'icmpv6',
                'ethertype': 'IPv6',
                'security_group_id': self.secgrp_uuid}),
            mock.call(**{
                'direction': 'ingress',
                'protocol': 'tcp',
                'ethertype': 'IPv6',
                'port_range_min': '22',
                'port_range_max': '22',
                'security_group_id': self.secgrp_uuid}),
            mock.call(**{
                'direction': 'ingress',
                'protocol': 'tcp',
                'ethertype': 'IPv6',
                'port_range_min': '9443',
                'port_range_max': '9443',
                'security_group_id': self.secgrp_uuid}),
            mock.call(**{
                'direction': 'ingress',
                'protocol': 'icmpv6',
                'ethertype': 'IPv6',
                'security_group_id': self.health_secgrp_uuid}),
            mock.call(**{
                'direction': 'ingress',
                'protocol': 'udp',
                'ethertype': 'IPv6',
                'port_range_min': octavia.OCTAVIA_HEALTH_LISTEN_PORT,
                'port_range_max': octavia.OCTAVIA_HEALTH_LISTEN_PORT,
                'security_group_id': self.health_secgrp_uuid}),
        ]

    def test_endpoint_type(self):
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        self.config.return_value = False
        self.assertEqual(api_crud.endpoint_type(), 'publicURL')
        self.config.return_value = True
        self.assertEqual(api_crud.endpoint_type(), 'internalURL')

    def test_endpoint_type_v3(self):
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        self.config.return_value = False
        self.assertEqual(api_crud.endpoint_type_v3(), 'public')
        self.config.return_value = True
        self.assertEqual(api_crud.endpoint_type_v3(), 'internal')

    def test_session_from_identity_service(self):
        self.patch_object(api_crud, 'keystone_identity')
        self.patch_object(api_crud, 'keystone_session')
        identity_service = mock.MagicMock()
        result = api_crud.session_from_identity_service(identity_service)
        self.keystone_identity.Password.assert_called_once_with(
            auth_url='{}://{}:{}/'
                     .format(identity_service.auth_protocol(),
                             identity_service.auth_host(),
                             identity_service.auth_port()),
            user_domain_name=identity_service.service_domain(),
            username=identity_service.service_username(),
            password=identity_service.service_password(),
            project_domain_name=identity_service.service_domain(),
            project_name=identity_service.service_tenant(),
        )
        self.keystone_session.Session.assert_called_once_with(
            auth=self.keystone_identity.Password(),
            verify='/etc/ssl/certs/ca-certificates.crt')
        self.assertEqual(result, self.keystone_session.Session())

    def test_get_nova_client(self):
        self.patch_object(api_crud, 'nova_client')
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        self.config.return_value = 'someregion'
        self.patch_object(api_crud, 'endpoint_type')
        self.endpoint_type.return_value = 'someeptype'
        api_crud.get_nova_client('somesession')
        self.config.assert_called_once_with('region')
        self.nova_client.Client.assert_called_once_with(
            '2', session='somesession', region_name='someregion',
            endpoint_type='someeptype')

    def test_get_nova_flavor(self):
        self.patch_object(api_crud, 'get_nova_client')
        self.patch_object(api_crud, 'nova_client')
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'keystone_exceptions')
        nova = mock.MagicMock()
        self.get_nova_client.return_value = nova
        flavor = mock.MagicMock()
        flavor.id = 'fake-id'
        flavor.name = 'charm-octavia'
        nova.flavors.list.return_value = [flavor]

        self.keystone_exceptions.catalog.EndpointNotFound = Exception
        self.keystone_exceptions.connection.ConnectFailure = Exception
        self.nova_client.exceptions.ClientException = Exception
        nova.flavors.list.side_effect = Exception
        identity_service = mock.MagicMock()
        with self.assertRaises(api_crud.APIUnavailable):
            api_crud.get_nova_flavor(identity_service)

        nova.flavors.list.side_effect = None
        api_crud.get_nova_flavor(identity_service)
        nova.flavors.list.assert_called_with(is_public=False)
        self.assertFalse(nova.flavors.create.called)
        nova.flavors.list.return_value = []
        nova.flavors.create.return_value = flavor
        api_crud.get_nova_flavor(identity_service)
        nova.flavors.create.assert_called_with('charm-octavia', 1024, 1, 8,
                                               is_public=False)

    def test_lookup_hm_port(self):
        conn = mock.MagicMock()
        port1 = mock.MagicMock()
        port2 = mock.MagicMock()
        conn.network.ports.return_value = [port1, port2]
        with self.assertRaises(api_crud.DuplicateResource):
            api_crud.lookup_hm_port(conn, 'fake-unit-name')
        conn.network.ports.return_value = [port1]
        self.assertEqual(
            api_crud.lookup_hm_port(conn, 'fake-unit-name'),
            port1)
        conn.network.ports.return_value = []
        self.assertEqual(
            api_crud.lookup_hm_port(conn, 'fake-unit-name'),
            None)

    def test_get_hm_port(self):
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'endpoint_type_v3')
        self.endpoint_type_v3.return_value = 'internal'
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        self.config.return_value = 'RegionOne'
        self.patch_object(connection, 'Connection')
        conn = mock.MagicMock()
        network = mock.MagicMock()
        self.Connection.return_value = conn
        network.id = 'fake-network-uuid'
        conn.network.networks.return_value = [network]
        health_secgrp = mock.MagicMock()
        health_secgrp.id = 'fake-secgrp-uuid'
        conn.network.security_groups.return_value = [health_secgrp]
        self.patch_object(api_crud.socket, 'gethostname')
        self.gethostname.return_value = 'fakehostname'
        port = mock.MagicMock()
        port.id = 'fake-port-uuid'
        port.mac_address = 'fake-mac-address'
        conn.network.create_port.return_value = port
        self.patch('subprocess.check_output', 'check_output')
        self.patch('charms.reactive.set_flag', 'set_flag')
        identity_service = mock.MagicMock()
        self.patch_object(api_crud, 'neutron_lib')
        self.neutron_lib.services.trunk.constants.TRUNK_SUBPORT_OWNER = (
            'fakeowner')
        self.patch_object(api_crud, 'lookup_hm_port')
        self.lookup_hm_port.return_value = None
        result = api_crud.get_hm_port(identity_service,
                                      'fake-unit-name')
        self.Connection.assert_called_once_with(
            session=self.session_from_identity_service(),
            network_interface='internal',
            region_name='RegionOne')
        conn.network.networks.assert_called_with(tags='charm-octavia')
        conn.network.security_groups.assert_called_with(
            tags='charm-octavia-health')
        self.lookup_hm_port.assert_called_once_with(
            conn, 'fake-unit-name')
        conn.network.create_port.assert_called_once_with(
            **{
                'admin_state_up': False,
                'binding:host_id': 'fakehostname',
                'device_owner': 'fakeowner',
                'security_groups': ['fake-secgrp-uuid'],
                'name': 'octavia-health-manager-'
                        'fake-unit-name-listen-port',
                'network_id': 'fake-network-uuid',
            })
        port.add_tag.assert_called_with(conn.network, 'charm-octavia')
        self.assertEqual(result, port)
        conn.network.create_port.reset_mock()
        result = api_crud.get_hm_port(identity_service,
                                      'fake-unit-name',
                                      host_id='fake-unit-name.fqdn')
        conn.network.create_port.assert_called_once_with(
            **{
                'admin_state_up': False,
                'binding:host_id': 'fake-unit-name.fqdn',
                'device_owner': 'fakeowner',
                'security_groups': ['fake-secgrp-uuid'],
                'name': 'octavia-health-manager-'
                        'fake-unit-name-listen-port',
                'network_id': 'fake-network-uuid',
            })
        self.assertEqual(result, port)

    def test_toggle_hm_port(self):
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'endpoint_type_v3')
        self.endpoint_type_v3.return_value = 'internal'
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        self.config.return_value = 'RegionOne'
        self.patch_object(connection, 'Connection')
        identity_service = mock.MagicMock()
        conn = mock.MagicMock()
        port = mock.MagicMock()
        self.Connection.return_value = conn
        port.id = 'fake-port-uuid'
        conn.network.ports.return_value = [port]
        api_crud.toggle_hm_port(identity_service, 'fake-unit-name')
        self.Connection.assert_called_once_with(
            session=self.session_from_identity_service(),
            network_interface='internal',
            region_name='RegionOne')
        conn.network.ports.assert_called_with(
            tags='charm-octavia-fake-unit-name')
        conn.network.update_port.assert_called_with(port, admin_state_up=True)

    def test_is_hm_port_bound(self):
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'endpoint_type_v3')
        self.endpoint_type_v3.return_value = 'internal'
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        self.config.return_value = 'RegionOne'
        self.patch_object(connection, 'Connection')
        self.patch_object(api_crud, 'lookup_hm_port')
        port_non_failure = mock.MagicMock()
        port_failure = mock.MagicMock()
        port_non_failure.binding_vif_type = 'nonfailure'
        port_failure.binding_vif_type = 'binding_failed'
        self.lookup_hm_port.return_value = None
        self.assertEqual(
            api_crud.is_hm_port_bound('ids', 'fake-unit-name'), None)
        self.lookup_hm_port.assert_called_once_with(
            mock.ANY, 'fake-unit-name')
        self.lookup_hm_port.return_value = port_non_failure
        self.assertTrue(api_crud.is_hm_port_bound('ids', 'fake-unit-name'))
        self.lookup_hm_port.return_value = port_failure
        self.assertFalse(api_crud.is_hm_port_bound('ids', 'fake-unit-name'))

    def test_wait_for_hm_port_bound(self):
        self.patch_object(api_crud.tenacity, 'Retrying')

        @contextlib.contextmanager
        def fake_context_manager():
            # TODO: Replace with `contextlib.nullcontext()` once we have
            # deprecated support for Python 3.4, 3.5 and 3.6
            yield None

        self.Retrying.return_value = [fake_context_manager()]
        self.patch_object(api_crud, 'is_hm_port_bound')
        self.is_hm_port_bound.return_value = True
        self.assertTrue(api_crud.wait_for_hm_port_bound(
            'ids', 'fake-unit-name'))
        self.Retrying.side_effect = api_crud.tenacity.RetryError(None)
        self.assertFalse(api_crud.wait_for_hm_port_bound(
            'ids', 'fake-unit-name'))

    def test_delete_hm_port(self):
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'endpoint_type_v3')
        self.endpoint_type_v3.return_value = 'internal'
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        self.config.return_value = 'RegionOne'
        identity_service = mock.MagicMock()
        self.patch_object(connection, 'Connection')
        conn = mock.MagicMock()
        port = mock.MagicMock()
        self.Connection.return_value = conn
        port.id = 'fake-port-uuid'
        conn.network.ports.return_value = [port]
        api_crud.delete_hm_port(identity_service, 'fake-unit-name')
        self.Connection.assert_called_once_with(
            session=self.session_from_identity_service(),
            network_interface='internal',
            region_name='RegionOne')
        conn.network.ports.assert_called_with(
            tags='charm-octavia-fake-unit-name')
        conn.network.delete_port.assert_called_with(port)

    def test_setup_hm_port(self):
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(connection, 'Connection')
        conn = mock.MagicMock()
        network = mock.MagicMock()
        self.Connection.return_value = conn
        network.id = 'fake-network-uuid'
        network.mtu = 9000
        conn.network.networks.return_value = [network]
        self.patch_object(octavia.ch_net_ip, 'get_iface_addr')
        self.get_iface_addr.return_value = [
            'fe80:db8:42%eth0', '2001:db8:42::42', '127.0.0.1'
        ]
        self.patch('subprocess.check_output', 'check_output')
        self.patch('subprocess.check_call', 'check_call')
        self.patch_object(api_crud, 'get_hm_port')
        self.patch_object(api_crud, 'toggle_hm_port')
        identity_service = mock.MagicMock()
        octavia_charm = mock.MagicMock()
        port = mock.MagicMock()
        port.id = 'fake-port-uuid'
        port.mac_address = 'fake-mac-address'
        port.admin_state_up = False
        port.binding_vif_type = 'binding_failed'
        port.status = 'DOWN'
        self.get_hm_port.return_value = port
        e = subprocess.CalledProcessError(returncode=1, cmd=None)
        e.output = ('Device "{}" does not exist.'
                    .format(api_crud.octavia.OCTAVIA_MGMT_INTF))
        self.check_output.side_effect = e
        api_crud.setup_hm_port(identity_service, octavia_charm)
        self.get_hm_port.assert_called_with(
            identity_service,
            octavia_charm.local_unit_name,
            host_id=None)
        self.check_output.assert_called_with(
            ['ip', 'link', 'show', api_crud.octavia.OCTAVIA_MGMT_INTF],
            stderr=-2, universal_newlines=True)
        self.check_call.assert_has_calls([
            mock.call(
                ['ovs-vsctl', '--', 'add-port',
                 api_crud.octavia.OCTAVIA_INT_BRIDGE,
                 api_crud.octavia.OCTAVIA_MGMT_INTF,
                 '--', 'set', 'Interface', api_crud.octavia.OCTAVIA_MGMT_INTF,
                 'type=internal',
                 '--', 'set', 'Interface', api_crud.octavia.OCTAVIA_MGMT_INTF,
                 'external-ids:iface-status=active',
                 '--', 'set', 'Interface', api_crud.octavia.OCTAVIA_MGMT_INTF,
                 'external-ids:attached-mac={}'.format(port.mac_address),
                 '--', 'set', 'Interface', api_crud.octavia.OCTAVIA_MGMT_INTF,
                 'external-ids:iface-id={}'.format(port.id),
                 '--', 'set', 'Interface', api_crud.octavia.OCTAVIA_MGMT_INTF,
                 'external-ids:skip_cleanup=true']),
            mock.call(['ip', 'link', 'set', 'o-hm0', 'up', 'address',
                       'fake-mac-address']),
        ])
        self.check_call.assert_has_calls([
            mock.call(['ovs-vsctl', '--', 'add-port', 'br-int', 'o-hm0', '--',
                       'set', 'Interface', 'o-hm0', 'type=internal', '--',
                       'set', 'Interface', 'o-hm0',
                       'external-ids:iface-status=active',
                       '--', 'set', 'Interface', 'o-hm0',
                       'external-ids:attached-mac=fake-mac-address', '--',
                       'set', 'Interface', 'o-hm0',
                       'external-ids:iface-id=fake-port-uuid',
                       '--', 'set', 'Interface', 'o-hm0',
                       'external-ids:skip_cleanup=true']),
            mock.call(['ip', 'link', 'set', 'o-hm0', 'up', 'address',
                       'fake-mac-address']),
            mock.call(['ovs-vsctl', 'set', 'Interface', 'o-hm0', 'mtu=9000']),
            mock.call(['ip', 'link', 'set', 'o-hm0', 'mtu', '9000'])])

    def test_get_port_ip_unit_map(self):
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'endpoint_type_v3')
        self.endpoint_type_v3.return_value = 'internal'
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        self.config.return_value = 'RegionOne'
        self.patch_object(connection, 'Connection')
        conn = mock.MagicMock()
        port1 = mock.MagicMock()
        port2 = mock.MagicMock()
        port1.name = 'octavia-health-manager-lb-0-listen-port'
        port1.status = 'ACTIVE'
        port1.fixed_ips = [{'ip_address': '2001:db8:42::1'}]
        port2.name = 'octavia-health-manager-lb-1-listen-port'
        port2.status = 'ACTIVE'
        port2.fixed_ips = [{'ip_address': '2001:db8:42::2'}]
        self.Connection.return_value = conn
        conn.network.ports.return_value = [port1, port2]
        identity_service = mock.MagicMock()
        self.assertEqual(api_crud.get_port_ip_unit_map(identity_service),
                         {'lb-0': '2001:db8:42::1', 'lb-1': '2001:db8:42::2'})
        self.Connection.assert_called_once_with(
            session=self.session_from_identity_service(),
            network_interface='internal',
            region_name='RegionOne')

    def test_get_mgmt_network_create(self):
        resource_tag = 'charm-octavia'
        self.patch_object(connection, 'Connection')
        identity_service = mock.MagicMock()
        conn = mock.MagicMock()
        network = mock.MagicMock()
        subnet = mock.MagicMock()
        router = mock.MagicMock()
        secgroup = mock.MagicMock()
        health_secgroup = mock.MagicMock()
        self.Connection.return_value = conn
        network.id = '83f1a860-9aed-4c0b-8b72-47195580a0c1'
        subnet.id = 'fake-subnet-uuid'
        subnet.cidr = 'fake-cidr'
        router.id = 'fake-router-uuid'
        secgroup.id = self.secgrp_uuid
        health_secgroup.id = self.health_secgrp_uuid
        conn.network.create_network.return_value = network
        conn.network.create_subnet.return_value = subnet
        conn.network.create_router.return_value = router
        conn.network.create_security_group.side_effect = [
            secgroup,
            health_secgroup,
        ]
        self.patch_object(api_crud, 'is_extension_enabled')
        self.is_extension_enabled.return_value = True
        result = api_crud.get_mgmt_network(identity_service)
        conn.network.networks.assert_called_once_with(tags=resource_tag)
        conn.network.create_network.assert_called_once_with(**{
            'name': octavia.OCTAVIA_MGMT_NET})

        conn.network.subnets.assert_called_once_with(network_id=network.id,
                                                     tags=resource_tag)
        conn.network.routers.assert_called_once_with(tags=resource_tag)
        conn.network.create_router.assert_called_once_with(
            **{'name': 'lb-mgmt', 'distributed': False})
        conn.network.security_groups.assert_any_call(tags=resource_tag)
        conn.network.security_groups.assert_any_call(tags=resource_tag +
                                                     '-health')
        conn.network.create_security_group_rule.assert_has_calls(
            self.security_group_rule_calls)
        self.assertEqual(result, (network, secgroup))

    def test_get_mgmt_network_exists(self):
        resource_tag = 'charm-octavia'
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'endpoint_type_v3')
        self.endpoint_type_v3.return_value = 'internal'
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        self.config.return_value = 'RegionOne'
        self.patch_object(connection, 'Connection')
        identity_service = mock.MagicMock()
        conn = mock.MagicMock()
        network = mock.MagicMock()
        subnet = mock.MagicMock()
        router = mock.MagicMock()
        secgroup = mock.MagicMock()
        health_secgroup = mock.MagicMock()
        self.Connection.return_value = conn
        network.id = '83f1a860-9aed-4c0b-8b72-47195580a0c1'
        subnet.id = 'fake-subnet-uuid'
        router.id = 'fake-router-uuid'
        secgroup.id = self.secgrp_uuid
        health_secgroup.id = self.health_secgrp_uuid
        conn.network.networks.return_value = [network]
        conn.network.subnets.return_value = [subnet]
        conn.network.routers.return_value = [router]
        conn.network.security_groups.side_effect = [[secgroup],
                                                    [health_secgroup]]
        self.patch_object(api_crud, 'openstack_exceptions',
                          name='openstack_exceptions')
        self.openstack_exceptions.ConflictException = \
            FakeNeutronConflictException
        conn.network.create_security_group_rule.side_effect = \
            FakeNeutronConflictException
        result = api_crud.get_mgmt_network(identity_service)
        self.Connection.assert_called_once_with(
            session=self.session_from_identity_service(),
            network_interface='internal',
            region_name='RegionOne')
        conn.network.networks.assert_called_once_with(tags=resource_tag)
        conn.network.subnets.assert_called_once_with(network_id=network.id,
                                                     tags=resource_tag)
        conn.network.routers.assert_called_once_with(tags=resource_tag)
        conn.network.security_groups.assert_has_calls([
            mock.call(tags=resource_tag),
            mock.call(tags=resource_tag + '-health'),
        ])
        conn.network.create_security_group_rule.assert_has_calls(
            self.security_group_rule_calls)
        self.assertEqual(result, (network, secgroup))

    def test_get_mgmt_network_exists_create_router(self):
        resource_tag = 'charm-octavia'
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'endpoint_type_v3')
        self.endpoint_type_v3.return_value = 'internal'
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        self.config.return_value = 'RegionOne'
        self.patch_object(connection, 'Connection')
        identity_service = mock.MagicMock()
        conn = mock.MagicMock()
        network = mock.MagicMock()
        subnet = mock.MagicMock()
        router = mock.MagicMock()
        secgrp = mock.MagicMock()
        health_secgrp = mock.MagicMock()
        self.Connection.return_value = conn
        network.id = '83f1a860-9aed-4c0b-8b72-47195580a0c1'
        subnet.id = 'fake-subnet-uuid'
        router.id = 'fake-router-uuid'
        secgrp.id = self.secgrp_uuid
        health_secgrp.id = self.health_secgrp_uuid
        conn.network.networks.return_value = [network]
        conn.network.subnets.return_value = [subnet]
        # network and subnet exists, but router doesn't
        conn.network.routers.return_value = []
        conn.network.create_router.return_value = router
        conn.network.security_groups.side_effect = [[secgrp], [health_secgrp]]
        self.patch_object(api_crud, 'openstack_exceptions',
                          name='openstack_exceptions')
        self.openstack_exceptions.ConflictException = \
            FakeNeutronConflictException
        conn.network.create_security_group_rule.side_effect = \
            FakeNeutronConflictException
        result = api_crud.get_mgmt_network(identity_service)
        self.Connection.assert_called_once_with(
            session=self.session_from_identity_service(),
            network_interface='internal',
            region_name='RegionOne')
        conn.network.networks.assert_called_once_with(tags=resource_tag)
        self.assertFalse(conn.network.create_networks.called)
        conn.network.subnets.assert_called_once_with(
            network_id=network.id,
            tags=resource_tag)
        self.assertFalse(conn.network.create_subnet.called)
        conn.network.routers.assert_called_once_with(tags=resource_tag)
        self.assertTrue(conn.network.create_router.called)
        conn.network.add_interface_to_router.assert_called_once_with(
            router,
            subnet_id='fake-subnet-uuid')
        conn.network.security_groups.assert_has_calls([
            mock.call(tags=resource_tag),
            mock.call(tags=resource_tag + '-health'),
        ])
        conn.network.create_security_group_rule.assert_has_calls(
            self.security_group_rule_calls)
        self.assertEqual(result, (network, secgrp))
