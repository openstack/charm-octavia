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

import mock
import subprocess

import charms_openstack.test_utils as test_utils

import charm.openstack.octavia as octavia  # for constants
import charm.openstack.api_crud as api_crud


class FakeNeutronConflictException(Exception):
    pass


class TestAPICrud(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.secgrp_uuid = 'fake-secgrp-uuid'
        self.health_secgrp_uuid = 'fake-health_secgrp-uuid'
        self.security_group_rule_calls = [
            mock.call(
                {'security_group_rule': {
                    'direction': 'ingress',
                    'protocol': 'icmpv6',
                    'ethertype': 'IPv6',
                    'security_group_id': self.secgrp_uuid}}),
            mock.call(
                {'security_group_rule': {
                    'direction': 'ingress',
                    'protocol': 'tcp',
                    'ethertype': 'IPv6',
                    'port_range_min': '22',
                    'port_range_max': '22',
                    'security_group_id': self.secgrp_uuid}}),
            mock.call(
                {'security_group_rule': {
                    'direction': 'ingress',
                    'protocol': 'tcp',
                    'ethertype': 'IPv6',
                    'port_range_min': '9443',
                    'port_range_max': '9443',
                    'security_group_id': self.secgrp_uuid}}),
            mock.call(
                {'security_group_rule': {
                    'direction': 'ingress',
                    'protocol': 'icmpv6',
                    'ethertype': 'IPv6',
                    'security_group_id': self.health_secgrp_uuid}}),
            mock.call(
                {'security_group_rule': {
                    'direction': 'ingress',
                    'protocol': 'udp',
                    'ethertype': 'IPv6',
                    'port_range_min': octavia.OCTAVIA_HEALTH_LISTEN_PORT,
                    'port_range_max': octavia.OCTAVIA_HEALTH_LISTEN_PORT,
                    'security_group_id': self.health_secgrp_uuid}}),
        ]

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

    def test_init_neutron_client(self):
        self.patch_object(api_crud, 'neutron_client')
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        api_crud.init_neutron_client('somesession')
        self.config.assert_called_once_with('region')
        self.neutron_client.Client.assert_called_once_with(
            session='somesession', region_name=self.config())

    def test_get_nova_flavor(self):
        self.patch_object(api_crud, 'nova_client')
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'keystone_exceptions')
        self.patch_object(api_crud.ch_core.hookenv, 'config')
        nova = mock.MagicMock()
        flavor = mock.MagicMock()
        flavor.id = 'fake-id'
        flavor.name = 'charm-octavia'
        nova.flavors.list.return_value = [flavor]
        self.nova_client.Client.return_value = nova
        self.config.return_value = 'someregion'

        self.keystone_exceptions.catalog.EndpointNotFound = Exception
        self.keystone_exceptions.connection.ConnectFailure = Exception
        self.nova_client.exceptions.ClientException = Exception
        nova.flavors.list.side_effect = Exception
        identity_service = mock.MagicMock()
        with self.assertRaises(api_crud.APIUnavailable):
            api_crud.get_nova_flavor(identity_service)

        nova.flavors.list.side_effect = None
        api_crud.get_nova_flavor(identity_service)
        self.config.assert_called_with('region')
        self.nova_client.Client.assert_called_with(
            '2',
            session=self.session_from_identity_service(),
            region_name='someregion')
        nova.flavors.list.assert_called_with(is_public=False)
        self.assertFalse(nova.flavors.create.called)
        nova.flavors.list.return_value = []
        nova.flavors.create.return_value = flavor
        api_crud.get_nova_flavor(identity_service)
        nova.flavors.create.assert_called_with('charm-octavia', 1024, 1, 8,
                                               is_public=False)

    def test_get_hm_port(self):
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'init_neutron_client')
        nc = mock.MagicMock()
        self.init_neutron_client.return_value = nc
        network_uuid = 'fake-network-uuid'
        nc.list_networks.return_value = {'networks': [{'id': network_uuid}]}
        health_secgrp_uuid = 'fake-secgrp-uuid'
        nc.list_security_groups.return_value = {
            'security_groups': [{'id': health_secgrp_uuid}]}
        self.patch_object(api_crud.socket, 'gethostname')
        self.gethostname.return_value = 'fakehostname'
        port_uuid = 'fake-port-uuid'
        port_mac_address = 'fake-mac-address'
        nc.create_port.return_value = {
            'port': {'id': port_uuid, 'mac_address': port_mac_address}}
        self.patch('subprocess.check_output', 'check_output')
        self.patch('charms.reactive.set_flag', 'set_flag')
        identity_service = mock.MagicMock()
        self.patch_object(api_crud, 'neutron_lib')
        self.neutron_lib.constants.DEVICE_OWNER_LOADBALANCERV2 = 'fakeowner'
        result = api_crud.get_hm_port(identity_service,
                                      'fake-unit-name',
                                      '192.0.2.42')
        self.init_neutron_client.assert_called_once_with(
            self.session_from_identity_service())
        nc.list_networks.assert_called_with(tags='charm-octavia')
        nc.list_security_groups.assert_called_with(
            tags='charm-octavia-health')
        nc.list_ports.assert_called_once_with(
            tags='charm-octavia-fake-unit-name')
        nc.create_port.assert_called_once_with(
            {
                'port': {
                    'admin_state_up': False,
                    'binding:host_id': 'fakehostname',
                    'device_owner': 'fakeowner',
                    'security_groups': ['fake-secgrp-uuid'],
                    'name': 'octavia-health-manager-'
                            'fake-unit-name-listen-port',
                    'network_id': 'fake-network-uuid',
                },
            })
        nc.add_tag.assert_called_with('ports', port_uuid, 'charm-octavia')
        self.assertEqual(result, {'id': 'fake-port-uuid',
                                  'mac_address': 'fake-mac-address'})
        nc.create_port.reset_mock()
        result = api_crud.get_hm_port(identity_service,
                                      'fake-unit-name',
                                      '192.0.2.42',
                                      host_id='fake-unit-name.fqdn')
        nc.create_port.assert_called_once_with(
            {
                'port': {
                    'admin_state_up': False,
                    'binding:host_id': 'fake-unit-name.fqdn',
                    'device_owner': 'fakeowner',
                    'security_groups': ['fake-secgrp-uuid'],
                    'name': 'octavia-health-manager-'
                            'fake-unit-name-listen-port',
                    'network_id': 'fake-network-uuid',
                },
            })
        self.assertEqual(result, {'id': 'fake-port-uuid',
                                  'mac_address': 'fake-mac-address'})

    def test_toggle_hm_port(self):
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'init_neutron_client')
        identity_service = mock.MagicMock()
        nc = mock.MagicMock()
        self.init_neutron_client.return_value = nc
        nc.list_ports.return_value = {'ports': [{'id': 'fake-port-uuid'}]}
        api_crud.toggle_hm_port(identity_service, 'fake-unit-name')
        self.init_neutron_client.assert_called_once_with(
            self.session_from_identity_service())
        nc.list_ports.assert_called_with(tags='charm-octavia-fake-unit-name')
        nc.update_port.assert_called_with('fake-port-uuid',
                                          {'port': {'admin_state_up': True}})

    def test_setup_hm_port(self):
        self.patch('subprocess.check_output', 'check_output')
        self.patch('subprocess.check_call', 'check_call')
        self.patch_object(api_crud, 'get_hm_port')
        self.patch_object(api_crud, 'toggle_hm_port')
        identity_service = mock.MagicMock()
        octavia_charm = mock.MagicMock()
        port_uuid = 'fake-port-uuid'
        port_mac_address = 'fake-mac-address'
        self.get_hm_port.return_value = {
            'id': port_uuid,
            'mac_address': port_mac_address,
            'admin_state_up': False,
            'status': 'DOWN',
        }
        e = subprocess.CalledProcessError(returncode=1, cmd=None)
        e.output = ('Device "{}" does not exist.'
                    .format(api_crud.octavia.OCTAVIA_MGMT_INTF))
        self.check_output.side_effect = e
        api_crud.setup_hm_port(identity_service, octavia_charm)
        self.get_hm_port.assert_called_with(
            identity_service,
            octavia_charm.local_unit_name,
            octavia_charm.local_address,
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
                 'external-ids:attached-mac={}'.format(port_mac_address),
                 '--', 'set', 'Interface', api_crud.octavia.OCTAVIA_MGMT_INTF,
                 'external-ids:iface-id={}'.format(port_uuid),
                 '--', 'set', 'Interface', api_crud.octavia.OCTAVIA_MGMT_INTF,
                 'external-ids:skip_cleanup=true']),
            mock.call(['ip', 'link', 'set', 'o-hm0', 'up', 'address',
                       'fake-mac-address']),
        ])
        self.check_call.assert_called_with(
            ['ip', 'link', 'set', api_crud.octavia.OCTAVIA_MGMT_INTF,
             'up', 'address', port_mac_address])
        self.toggle_hm_port.assert_called

    def test_get_port_ips(self):
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'init_neutron_client')
        nc = mock.MagicMock()
        self.init_neutron_client.return_value = nc
        nc.list_ports.return_value = {
            'ports': [
                {'fixed_ips': [{'ip_address': '2001:db8:42::42'}]},
                {'fixed_ips': [{'ip_address': '2001:db8:42::51'}]},
            ],
        }
        identity_service = mock.MagicMock()
        self.assertEquals(api_crud.get_port_ips(identity_service),
                          ['2001:db8:42::42',
                           '2001:db8:42::51'])
        self.init_neutron_client.assert_called_once_with(
            self.session_from_identity_service())

    def test_get_mgmt_network_create(self):
        resource_tag = 'charm-octavia'
        self.patch_object(api_crud, 'neutron_client')
        identity_service = mock.MagicMock()
        nc = mock.MagicMock()
        self.neutron_client.Client.return_value = nc
        network_uuid = '83f1a860-9aed-4c0b-8b72-47195580a0c1'
        nc.create_network.return_value = {'network': {'id': network_uuid}}
        nc.create_subnet.return_value = {
            'subnets': [{'id': 'fake-subnet-uuid', 'cidr': 'fake-cidr'}]}
        nc.create_router.return_value = {
            'router': {'id': 'fake-router-uuid'}}
        nc.create_security_group.side_effect = [
            {'security_group': {'id': self.secgrp_uuid}},
            {'security_group': {'id': self.health_secgrp_uuid}},
        ]
        self.patch_object(api_crud, 'is_extension_enabled')
        self.is_extension_enabled.return_value = True
        result = api_crud.get_mgmt_network(identity_service)
        nc.list_networks.assert_called_once_with(tags=resource_tag)
        nc.create_network.assert_called_once_with({
            'network': {'name': octavia.OCTAVIA_MGMT_NET}})

        nc.list_subnets.assert_called_once_with(tags=resource_tag)
        nc.list_routers.assert_called_once_with(tags=resource_tag)
        nc.create_router.assert_called_once_with(
            {'router': {'name': 'lb-mgmt', 'distributed': False}})
        nc.list_security_groups.assert_any_call(tags=resource_tag)
        nc.list_security_groups.assert_any_call(tags=resource_tag + '-health')
        nc.create_security_group_rule.assert_has_calls(
            self.security_group_rule_calls)
        self.assertEqual(result, (
            {'id': network_uuid},
            {'id': self.secgrp_uuid},),
        )

    def test_get_mgmt_network_exists(self):
        resource_tag = 'charm-octavia'
        self.patch_object(api_crud, 'session_from_identity_service')
        self.patch_object(api_crud, 'init_neutron_client')
        identity_service = mock.MagicMock()
        nc = mock.MagicMock()
        self.init_neutron_client.return_value = nc
        network_uuid = '83f1a860-9aed-4c0b-8b72-47195580a0c1'
        nc.list_networks.return_value = {'networks': [{'id': network_uuid}]}
        nc.list_subnets.return_value = {
            'subnets': [{'id': 'fake-subnet-uuid'}]}
        nc.list_routers.return_value = {
            'routers': [{'id': 'fake-router-uuid'}]}
        nc.list_security_groups.side_effect = [
            {'security_groups': [{'id': self.secgrp_uuid}]},
            {'security_groups': [{'id': self.health_secgrp_uuid}]},
        ]

        self.patch_object(api_crud.neutronclient.common, 'exceptions',
                          name='neutron_exceptions')
        self.neutron_exceptions.Conflict = FakeNeutronConflictException
        nc.create_security_group_rule.side_effect = \
            FakeNeutronConflictException
        result = api_crud.get_mgmt_network(identity_service)
        self.init_neutron_client.assert_called_once_with(
            self.session_from_identity_service())
        nc.list_networks.assert_called_once_with(tags=resource_tag)
        nc.list_subnets.assert_called_once_with(tags=resource_tag)
        nc.list_routers.assert_called_once_with(tags=resource_tag)
        nc.list_security_groups.assert_has_calls([
            mock.call(tags=resource_tag),
            mock.call(tags=resource_tag + '-health'),
        ])
        nc.create_security_group_rule.assert_has_calls(
            self.security_group_rule_calls)
        self.assertEqual(result, (
            {'id': network_uuid},
            {'id': self.secgrp_uuid},),
        )
