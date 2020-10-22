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

# NOTE(fnordahl) imported dependencies are included in the reactive charm
# ``wheelhouse.txt`` and are isolated from any system installed payload managed
# by the charm.
#
# An alternative could be to execute the openstack CLI to manage the resources,
# but at the time of this writing we can not due to it producing invalid JSON
# and YAML for the ``fixed_ips`` field when providing details for a Neutron
# port.

import base64
import neutronclient
import socket
import subprocess

from keystoneauth1 import identity as keystone_identity
from keystoneauth1 import session as keystone_session
from keystoneauth1 import exceptions as keystone_exceptions
from neutronclient.v2_0 import client as neutron_client
from novaclient import client as nova_client

import neutron_lib.constants

import charm.openstack.octavia as octavia  # for constants

import charmhelpers.core as ch_core


NEUTRON_TEMP_EXCS = (keystone_exceptions.catalog.EndpointNotFound,
                     keystone_exceptions.connection.ConnectFailure,
                     keystone_exceptions.discovery.DiscoveryFailure,
                     keystone_exceptions.http.ServiceUnavailable,
                     keystone_exceptions.http.InternalServerError,
                     neutronclient.common.exceptions.ServiceUnavailable,
                     neutronclient.common.exceptions.BadRequest,
                     neutronclient.common.exceptions.NeutronClientException)
SYSTEM_CA_BUNDLE = '/etc/ssl/certs/ca-certificates.crt'


class APIUnavailable(Exception):
    """Exception raised when a temporary availability issue occurs."""

    def __init__(self, service_type, resource_type, upstream_exception):
        """Initialize APIUnavailable exception.

        :param service_type: Name of service we had issues with (e.g. `nova`).
        :type service_type: str
        :param resource_type: Name of resource we had issues with
                              (e.g. `flavors`)
        :type resource_type: str
        :param upstream_exception: Reference to the exception caught
        :type upstream_exception: BaseException derived object
        """
        self.service_type = service_type
        self.resource_type = resource_type
        self.upstream_exception = upstream_exception


class DuplicateResource(Exception):
    """Exception raised when resource query result in multiple entries."""

    def __init__(self, service_type, resource_type, data=None):
        """Initialize DuplicateResource exception.

        :param service_type: Name of service we had issues with (e.g. `nova`).
        :type service_type: str
        :param resource_type: Name of resource we had issues with
                              (e.g. `flavors`)
        :type resource_type: str
        :param data: Data from search result
        :type data: (Optional)any
        """
        self.service_type = service_type
        self.resource_type = resource_type
        self.data = data


def endpoint_type():
    """Determine endpoint type to use.

    :returns: endpoint type
    :rtype: str
    """
    if ch_core.hookenv.config('use-internal-endpoints'):
        return 'internalURL'
    return 'publicURL'


def session_from_identity_service(identity_service):
    """Get Keystone Session from `identity-service` relation.

    :param identity_service: reactive Endpoint
    :type identity_service: RelationBase
    :returns: Keystone session
    :rtype: keystone_session.Session
    """
    auth = keystone_identity.Password(
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
    # NOTE(fnordahl): LP: #1819205 since the charm bundles its dependencies we
    # do not get the patched python ``certifi`` package that ponits at the
    # system wide certificate store.  We need to point clients there ourself.
    return keystone_session.Session(auth=auth, verify=SYSTEM_CA_BUNDLE)


def init_neutron_client(keystone_session):
    """Instantiate neutron client

    :param keystone_session: Keystone client auth session
    :type keystone_session.Session
    :returns: Neutron client
    :rtype: neutron_client.Client
    """
    return neutron_client.Client(session=keystone_session,
                                 region_name=ch_core.hookenv.config('region'),
                                 endpoint_type=endpoint_type(),
                                 )


def get_nova_client(keystone_session):
    """Get Nova client

    :param keystone_session: Keystone client auth session
    :type keystone_session.Session
    :returns: Nova client
    :rtype: nova_client.Client
    """
    return nova_client.Client('2',
                              session=keystone_session,
                              region_name=ch_core.hookenv.config('region'),
                              endpoint_type=endpoint_type(),
                              )


def is_extension_enabled(neutron_client, ext_alias):
    """Check for presence of Neutron extension

    :param neutron_client:
    :type neutron_client:
    :returns: True if Neutron lists extension, False otherwise
    :rtype: bool
    """
    for extension in neutron_client.list_extensions().get('extensions', []):
        if extension.get('alias') == ext_alias:
            return True
    return False


def get_nova_flavor(identity_service):
    """Get or create private Nova flavor for use with Octavia.

    A side effect of calling this function is that Nova flavors are
    created if they do not already exist.

    :param identity_service: reactive Endpoint of type ``identity-service``
    :type identity_service: RelationBase class
    :returns: Nova Flavor Resource object
    :rtype: novaclient.v2.flavors.Flavor
    """
    try:
        session = session_from_identity_service(identity_service)
        nova = get_nova_client(session)
        flavors = nova.flavors.list(is_public=False)
        for flavor in flavors:
            if flavor.name == 'charm-octavia':
                return flavor

        # create flavor
        return nova.flavors.create('charm-octavia', 1024, 1, 8,
                                   is_public=False)
    except (keystone_exceptions.catalog.EndpointNotFound,
            keystone_exceptions.connection.ConnectFailure,
            nova_client.exceptions.ClientException) as e:
        raise APIUnavailable('nova', 'flavors', e)


def create_nova_keypair(identity_service, amp_key_name):
    """Create a nova keypair to use with Amphora images to allow ssh access
    e.g. for debug purposes.
    """
    pubkey = ch_core.hookenv.config('amp-ssh-pub-key')
    if not pubkey:
        ch_core.hookenv.log('No pub key provided - cannot create amp-ssh-key '
                            'keypair', level=ch_core.hookenv.WARNING)
        return

    pubkey_decoded = base64.b64decode(pubkey).strip().decode()
    try:
        session = session_from_identity_service(identity_service)
        nova = get_nova_client(session)
        keys = nova.keypairs.list()
        for key in keys:
            if key.name == amp_key_name:
                ch_core.hookenv.log("Nova keypair with name '{}' already "
                                    "exists - skipping create"
                                    .format(amp_key_name),
                                    level=ch_core.hookenv.INFO)
                return

        # create keypair
        ch_core.hookenv.log("Creating nova keypair '{}'".format(amp_key_name),
                            level=ch_core.hookenv.DEBUG)
        return nova.keypairs.create(name=amp_key_name,
                                    public_key=pubkey_decoded)
    except (keystone_exceptions.catalog.EndpointNotFound,
            keystone_exceptions.connection.ConnectFailure,
            nova_client.exceptions.ClientException) as e:
        raise APIUnavailable('nova', 'keypairs', e)


def lookup_hm_port(nc, local_unit_name):
    """Retrieve port object for Neutron port for local unit.

    :param nc: Neutron Client object
    :type nc: neutron_client.Client
    :param local_unit_name: Name of juju unit, used to build tag name for port
    :type local_unit_name: str
    :returns: Port data
    :rtype: Optional[Dict[str,any]]
    :raises: DuplicateResource or any exceptions raised by Keystone and Neutron
             clients.
    """
    resp = nc.list_ports(tags='charm-octavia-{}'.format(local_unit_name))
    n_resp = len(resp.get('ports', []))
    if n_resp == 1:
        return (resp['ports'][0])
    elif n_resp > 1:
        raise DuplicateResource('neutron', 'ports', data=resp)
    else:
        return


def get_hm_port(identity_service, local_unit_name, local_unit_address,
                host_id=None):
    """Get or create a per unit Neutron port for Octavia Health Manager.

    A side effect of calling this function is that a port is created if one
    does not already exist.

    :param identity_service: reactive Endpoint of type ``identity-service``
    :type identity_service: RelationBase class
    :param local_unit_name: Name of juju unit, used to build tag name for port
    :type local_unit_name: str
    :param local_unit_address: DNS resolvable IP address of unit, used to
                               build Neutron port ``binding:host_id``
    :type local_unit_address: str
    :param host_id: Identifier used by SDN for binding the port
    :type host_id: Option[None,str]
    :returns: Port details extracted from result of call to
              neutron_client.list_ports or neutron_client.create_port
    :rtype: dict
    :raises: api_crud.APIUnavailable, api_crud.DuplicateResource
    """
    session = session_from_identity_service(identity_service)
    try:
        nc = init_neutron_client(session)
        resp = nc.list_networks(tags='charm-octavia')
    except NEUTRON_TEMP_EXCS as e:
        raise APIUnavailable('neutron', 'networks', e)

    network = None
    n_resp = len(resp.get('networks', []))
    if n_resp == 1:
        network = resp['networks'][0]
    elif n_resp > 1:
        raise DuplicateResource('neutron', 'networks', data=resp)
    else:
        ch_core.hookenv.log('No network tagged with `charm-octavia` exists, '
                            'deferring port setup awaiting network and port '
                            '(re-)creation.', level=ch_core.hookenv.WARNING)
        return
    health_secgrp = None

    try:
        resp = nc.list_security_groups(tags='charm-octavia-health')
    except NEUTRON_TEMP_EXCS as e:
        raise APIUnavailable('neutron', 'security_groups', e)

    n_resp = len(resp.get('security_groups', []))
    if n_resp == 1:
        health_secgrp = resp['security_groups'][0]
    elif n_resp > 1:
        raise DuplicateResource('neutron', 'security_groups', data=resp)
    else:
        ch_core.hookenv.log('No security group tagged with '
                            '`charm-octavia-health` exists, deferring '
                            'port setup awaiting network and port '
                            '(re-)creation...',
                            level=ch_core.hookenv.WARNING)
        return

    try:
        hm_port = lookup_hm_port(nc, local_unit_name)
    except NEUTRON_TEMP_EXCS as e:
        raise APIUnavailable('neutron', 'ports', e)

    port_template = {
        'port': {
            # avoid race with OVS agent attempting to bind port
            # before it is created in the local units OVSDB
            'admin_state_up': False,
            'binding:host_id': host_id or socket.gethostname(),
            # NOTE(fnordahl): device_owner has special meaning
            # for Neutron [0], and things may break if set to
            # an arbritary value.  Using a value known by Neutron
            # is_dvr_serviced() function [1] gets us the correct
            # rules appiled to the port to allow IPv6 Router
            # Advertisement packets through LP: #1813931
            # 0: https://github.com/openstack/neutron/blob/
            #      916347b996684c82b29570cd2962df3ea57d4b16/
            #      neutron/plugins/ml2/drivers/openvswitch/
            #      agent/ovs_dvr_neutron_agent.py#L592
            # 1: https://github.com/openstack/neutron/blob/
            #      50308c03c960bd6e566f328a790b8e05f5e92ead/
            #      neutron/common/utils.py#L200
            'device_owner': (
                neutron_lib.constants.DEVICE_OWNER_LOADBALANCERV2),
            'security_groups': [
                health_secgrp['id'],
            ],
            'name': 'octavia-health-manager-{}-listen-port'
                    .format(local_unit_name),
            'network_id': network['id'],
        },
    }
    if not hm_port:
        # create new port
        try:
            resp = nc.create_port(port_template)
            hm_port = resp['port']
            ch_core.hookenv.log('Created port {}'.format(hm_port['id']),
                                ch_core.hookenv.INFO)
            # unit specific tag is used by each unit to load their state
            nc.add_tag('ports', hm_port['id'],
                       'charm-octavia-{}'
                       .format(local_unit_name))
            # charm-wide tag is used by leader to load cluster state and build
            # ``controller_ip_port_list`` configuration property
            nc.add_tag('ports', hm_port['id'], 'charm-octavia')
        except NEUTRON_TEMP_EXCS as e:
            raise APIUnavailable('neutron', 'ports', e)
    elif hm_port.get(
            'binding:host_id') != port_template['port']['binding:host_id']:
        # Ensure binding:host_id is up to date on a existing port
        #
        # In the event of a need to update it, we bring the port down to make
        # sure Neutron rebuilds the port correctly.
        #
        # Our caller, ``setup_hm_port``, will toggle the port admin status.
        try:
            nc.update_port(hm_port['id'], {
                'port': {
                    'admin_state_up': False,
                    'binding:host_id': port_template['port'][
                        'binding:host_id'],
                }
            })
        except NEUTRON_TEMP_EXCS as e:
            raise APIUnavailable('neutron', 'ports', e)
    return hm_port


def toggle_hm_port(identity_service, local_unit_name, enabled=True):
    """Toggle administrative state of Neutron port for local unit.

    :param identity_service: reactive Endpoint of type ``identity-service``
    :type identity_service: RelationBase class
    :param local_unit_name: Name of juju unit, used to build tag name for port
    :type local_unit_name: str
    :param enabled: Desired state
    :type enabled: bool
    :raises: api_crud.APIUnavailable
    """
    session = session_from_identity_service(identity_service)
    try:
        nc = init_neutron_client(session)
        port = lookup_hm_port(nc, local_unit_name)
    except NEUTRON_TEMP_EXCS as e:
        raise APIUnavailable('neutron', 'ports', e)
    if not port:
        ch_core.hookenv.log('When attempting to toggle admin status of port, '
                            'we unexpectedly found that no port exists for '
                            'unit.',
                            level=ch_core.hookenv.WARNING)
        return
    nc.update_port(port['id'], {'port': {'admin_state_up': enabled}})


def setup_hm_port(identity_service, octavia_charm, host_id=None):
    """Create a per unit Neutron and OVS port for Octavia Health Manager.

    This is used to plug the unit into the overlay network for direct
    communication with the octavia managed load balancer instances running
    within the deployed cloud.

    :param identity_service: reactive Endpoint of type ``identity-service``
    :type identity_service: RelationBase class
    :param ocataiva_charm: charm instance
    :type octavia_charm: OctaviaCharm class instance
    :param host_id: Identifier used by SDN for binding the port
    :type host_id: Option[None,str]
    :retruns: True on change to local unit, False otherwise
    :rtype: bool
    :raises: api_crud.APIUnavailable, api_crud.DuplicateResource
    """
    unit_changed = False
    hm_port = get_hm_port(
        identity_service,
        octavia_charm.local_unit_name,
        octavia_charm.local_address,
        host_id=host_id)
    if not hm_port:
        ch_core.hookenv.log('No network tagged with `charm-octavia` '
                            'exists, deferring port setup awaiting '
                            'network and port (re-)creation...',
                            level=ch_core.hookenv.WARNING)
        return
    HM_PORT_MAC = hm_port['mac_address']
    HM_PORT_ID = hm_port['id']
    try:
        subprocess.check_output(
            ['ip', 'link', 'show', octavia.OCTAVIA_MGMT_INTF],
            stderr=subprocess.STDOUT, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        if 'does not exist' in e.output:
            subprocess.check_call(
                ['ovs-vsctl', '--', 'add-port',
                 octavia.OCTAVIA_INT_BRIDGE, octavia.OCTAVIA_MGMT_INTF,
                 '--', 'set', 'Interface', octavia.OCTAVIA_MGMT_INTF,
                 'type=internal',
                 '--', 'set', 'Interface', octavia.OCTAVIA_MGMT_INTF,
                 'external-ids:iface-status=active',
                 '--', 'set', 'Interface', octavia.OCTAVIA_MGMT_INTF,
                 'external-ids:attached-mac={}'.format(HM_PORT_MAC),
                 '--', 'set', 'Interface', octavia.OCTAVIA_MGMT_INTF,
                 'external-ids:iface-id={}'.format(HM_PORT_ID),
                 '--', 'set', 'Interface', octavia.OCTAVIA_MGMT_INTF,
                 'external-ids:skip_cleanup=true',
                 ])
            ch_core.hookenv.log('add OVS port', level=ch_core.hookenv.INFO)
            # post boot reconfiguration of systemd-networkd does not appear to
            # set the MAC addresss on the interface, do it ourself.
            subprocess.check_call(
                ['ip', 'link', 'set', octavia.OCTAVIA_MGMT_INTF,
                 'up', 'address', HM_PORT_MAC])
            # Signal that change has been made to local unit
            unit_changed = True
        else:
            # unknown error, raise
            raise e
    if not hm_port['admin_state_up'] or hm_port['status'] == 'DOWN':
        # NOTE(fnordahl) there appears to be a handful of race conditions
        # hitting us sometimes making the newly created ports unusable.
        # as a workaround we toggle the port belonging to us.
        # a disable/enable round trip makes Neutron reset the port
        # configuration which resolves these situations.
        ch_core.hookenv.log('toggling port {} (admin_state_up: {} '
                            'status: {})'
                            .format(hm_port['id'],
                                    hm_port['admin_state_up'],
                                    hm_port['status']),
                            level=ch_core.hookenv.INFO)

        toggle_hm_port(identity_service,
                       octavia_charm.local_unit_name,
                       enabled=False)
        toggle_hm_port(identity_service,
                       octavia_charm.local_unit_name,
                       enabled=True)
    return unit_changed


def get_port_ips(identity_service):
    """Extract IP information from Neutron ports tagged with ``charm-octavia``

    :param identity_service: reactive Endpoint of type ``identity-service``
    :type identity_service: RelationBase class
    :returns: List of IP addresses extracted from port details in search result
    :rtype: list of str
    :raises: api_crud.APIUnavailable
    """
    session = session_from_identity_service(identity_service)
    try:
        nc = init_neutron_client(session)
        resp = nc.list_ports(tags='charm-octavia')
    except NEUTRON_TEMP_EXCS as e:
        raise APIUnavailable('neutron', 'ports', e)

    neutron_ip_list = []
    for port in resp['ports']:
        for ip_info in port['fixed_ips']:
            neutron_ip_list.append(ip_info['ip_address'])

    return neutron_ip_list


def get_mgmt_network(identity_service, create=True):
    """Get or create Neutron network resources for Octavia.

    A side effect of calling this function is that network resources are
    created if they do not already exist, unless ``create`` is set to False.

    :param identity_service: reactive Endpoint of type ``identity-service``
    :type identity_service: RelationBase class
    :param create: (Optional and default) Create resources that do not exist
    :type: create: bool
    :returns: List of IP addresses extracted from port details in search result
    :rtype: list of str
    :raises: api_crud.APIUnavailable, api_crud.DuplicateResource
    """
    session = session_from_identity_service(identity_service)
    try:
        nc = init_neutron_client(session)
        resp = nc.list_networks(tags='charm-octavia')
    except NEUTRON_TEMP_EXCS as e:
        raise APIUnavailable('neutron', 'networks', e)

    n_resp = len(resp.get('networks', []))
    if n_resp == 1:
        network = resp['networks'][0]
    elif n_resp > 1:
        raise DuplicateResource('neutron', 'networks', data=resp)
    elif not create:
        ch_core.hookenv.log('No network tagged with `charm-octavia` exists, '
                            'and we are configured to not create resources.'
                            'Awaiting end user resource creation.',
                            level=ch_core.hookenv.WARNING)
        return
    else:
        try:
            resp = nc.create_network({
                'network': {'name': octavia.OCTAVIA_MGMT_NET}})
            network = resp['network']
            nc.add_tag('networks', network['id'], 'charm-octavia')
            ch_core.hookenv.log('Created network {}'.format(network['id']),
                                level=ch_core.hookenv.INFO)
        except NEUTRON_TEMP_EXCS as e:
            raise APIUnavailable('neutron', 'networks', e)

    try:
        resp = nc.list_subnets(tags='charm-octavia')
    except NEUTRON_TEMP_EXCS as e:
        raise APIUnavailable('neutron', 'subnets', e)

    n_resp = len(resp.get('subnets', []))
    subnets = None
    if n_resp < 1 and create:
        # make rfc4193 Unique Local IPv6 Unicast Addresses from network UUID
        rfc4193_addr = 'fc00'
        for n in [0, 4, 8]:
            rfc4193_addr += ':' + network['id'].split('-')[4][n:n + 4]
        rfc4193_addr += '::/64'
        try:
            resp = nc.create_subnet(
                {
                    'subnets': [
                        {
                            'name': octavia.OCTAVIA_MGMT_SUBNET + 'v6',
                            'ip_version': 6,
                            'ipv6_address_mode': 'slaac',
                            'ipv6_ra_mode': 'slaac',
                            'cidr': rfc4193_addr,
                            'network_id': network['id'],
                        },
                    ],
                })
            subnets = resp['subnets']
            for subnet in resp['subnets']:
                nc.add_tag('subnets', subnet['id'], 'charm-octavia')
                ch_core.hookenv.log('Created subnet {} with cidr {}'
                                    .format(subnet['id'], subnet['cidr']),
                                    level=ch_core.hookenv.INFO)
        except NEUTRON_TEMP_EXCS as e:
            raise APIUnavailable('neutron', 'subnets', e)

    try:
        resp = nc.list_routers(tags='charm-octavia')
    except NEUTRON_TEMP_EXCS as e:
        raise APIUnavailable('neutron', 'routers', e)

    n_resp = len(resp.get('routers', []))
    router = None
    if n_resp < 1 and create:
        try:
            body = {
                'router': {
                    'name': octavia.OCTAVIA_MGMT_NAME_PREFIX,
                },
            }
            # NOTE(fnordahl): Using the ``distributed`` key in a request to
            # Neutron is an error when the DVR extension is not enabled.
            if is_extension_enabled(nc, 'dvr'):
                # NOTE(fnordahl): When DVR is enabled we want to use a
                # centralized router to support assigning addresses with IPv6
                # RA. LP: #1843557
                body['router'].update({'distributed': False})
            resp = nc.create_router(body)
            router = resp['router']
            nc.add_tag('routers', router['id'], 'charm-octavia')
            ch_core.hookenv.log('Created router {}'.format(router['id']),
                                level=ch_core.hookenv.INFO)
            for subnet in subnets:
                nc.add_interface_router(router['id'],
                                        {'subnet_id': subnet['id']})
                ch_core.hookenv.log('Added interface from router {} '
                                    'to subnet {}'
                                    .format(router['id'], subnet['id']),
                                    level=ch_core.hookenv.INFO)
        except NEUTRON_TEMP_EXCS as e:
            raise APIUnavailable('neutron', 'routers', e)

    try:
        resp = nc.list_security_groups(tags='charm-octavia')
    except NEUTRON_TEMP_EXCS as e:
        raise APIUnavailable('neutron', 'security_groups', e)

    n_resp = len(resp.get('security_groups', []))
    if n_resp == 1:
        secgrp = resp['security_groups'][0]
    elif n_resp > 1:
        raise DuplicateResource('neutron', 'security_groups', data=resp)
    elif not create:
        ch_core.hookenv.log('No security group tagged with `charm-octavia` '
                            'exists, and we are configured to not create '
                            'resources.  Awaiting end user resource '
                            'creation.',
                            level=ch_core.hookenv.WARNING)
        return
    else:
        try:
            resp = nc.create_security_group(
                {
                    'security_group': {
                        'name': octavia.OCTAVIA_MGMT_SECGRP,
                    },
                })
            secgrp = resp['security_group']
            nc.add_tag('security_groups', secgrp['id'], 'charm-octavia')
            ch_core.hookenv.log('Created security group "{}"'
                                .format(secgrp['id']),
                                level=ch_core.hookenv.INFO)
        except NEUTRON_TEMP_EXCS as e:
            raise APIUnavailable('neutron', 'security_groups', e)

    if create:
        security_group_rules = [
            {
                'direction': 'ingress',
                'protocol': 'icmpv6',
                'ethertype': 'IPv6',
                'security_group_id': secgrp['id'],
            },
            {
                'direction': 'ingress',
                'protocol': 'tcp',
                'ethertype': 'IPv6',
                'port_range_min': '22',
                'port_range_max': '22',
                'security_group_id': secgrp['id'],
            },
            {
                'direction': 'ingress',
                'protocol': 'tcp',
                'ethertype': 'IPv6',
                'port_range_min': '9443',
                'port_range_max': '9443',
                'security_group_id': secgrp['id'],
            },
        ]
        for rule in security_group_rules:
            try:
                nc.create_security_group_rule({'security_group_rule': rule})
            except neutronclient.common.exceptions.Conflict:
                pass
            except NEUTRON_TEMP_EXCS as e:
                raise APIUnavailable('neutron', 'security_group_rules', e)

    try:
        resp = nc.list_security_groups(tags='charm-octavia-health')
    except NEUTRON_TEMP_EXCS as e:
        raise APIUnavailable('neutron', 'security_groups', e)

    n_resp = len(resp.get('security_groups', []))
    if n_resp == 1:
        health_secgrp = resp['security_groups'][0]
    elif n_resp > 1:
        raise DuplicateResource('neutron', 'security_groups', data=resp)
    elif not create:
        ch_core.hookenv.log('No security group tagged with '
                            '`charm-octavia-health` exists, and we are '
                            'configured to not create resources.  Awaiting '
                            'end user resource creation.',
                            level=ch_core.hookenv.WARNING)
        return
    else:
        try:
            resp = nc.create_security_group(
                {
                    'security_group': {
                        'name': octavia.OCTAVIA_HEALTH_SECGRP,
                    },
                })
            health_secgrp = resp['security_group']
            nc.add_tag('security_groups', health_secgrp['id'],
                       'charm-octavia-health')
            ch_core.hookenv.log('Created security group "{}"'
                                .format(health_secgrp['id']),
                                level=ch_core.hookenv.INFO)
        except NEUTRON_TEMP_EXCS as e:
            raise APIUnavailable('neutron', 'security_groups', e)
    if create:
        health_security_group_rules = [
            {
                'direction': 'ingress',
                'protocol': 'icmpv6',
                'ethertype': 'IPv6',
                'security_group_id': health_secgrp['id'],
            },
            {
                'direction': 'ingress',
                'protocol': 'udp',
                'ethertype': 'IPv6',
                'port_range_min': octavia.OCTAVIA_HEALTH_LISTEN_PORT,
                'port_range_max': octavia.OCTAVIA_HEALTH_LISTEN_PORT,
                'security_group_id': health_secgrp['id'],
            },
        ]
        for rule in health_security_group_rules:
            try:
                nc.create_security_group_rule({'security_group_rule': rule})
            except neutronclient.common.exceptions.Conflict:
                pass
            except NEUTRON_TEMP_EXCS as e:
                raise APIUnavailable('neutron', 'security_groups', e)
    resp = nc.list_security_group_rules(security_group_id=health_secgrp['id'])
    return (network, secgrp)


def set_service_quotas_unlimited(identity_service):
    """Set services project quotas to unlimited.

    :param identity_service: reactive Endpoint of type ``identity-service``
    :type identity_service: RelationBase class
    :returns: None
    :rtype: None
    :raises: api_crud.APIUnavailable
    """
    try:
        _ul = -1
        session = session_from_identity_service(identity_service)
        nova = get_nova_client(session)
        nova.quotas.update(
            identity_service.service_tenant_id(),
            cores=_ul, ram=_ul, instances=_ul)
        nc = init_neutron_client(session)
        nc.update_quota(
            identity_service.service_tenant_id(),
            body={
                "quota": {
                    "port": _ul, "security_group": _ul,
                    "security_group_rule": _ul, "network": _ul, "subnet": _ul,
                    "floatingip": _ul, "router": _ul, "rbac_policy": _ul}})
    except (keystone_exceptions.catalog.EndpointNotFound,
            keystone_exceptions.connection.ConnectFailure,
            nova_client.exceptions.ClientException) as e:
        raise APIUnavailable('nova', 'quotas', e)
    except NEUTRON_TEMP_EXCS as e:
        raise APIUnavailable('neutron', 'quotas', e)
