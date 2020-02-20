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
import uuid

import charms.reactive as reactive
import charms.leadership as leadership

import charms_openstack.bus
import charms_openstack.charm as charm
import charms_openstack.ip as os_ip

import charmhelpers.core as ch_core

import charm.openstack.api_crud as api_crud
import charm.openstack.octavia as octavia

charms_openstack.bus.discover()

charm.use_defaults(
    'charm.installed',
    'amqp.connected',
    'shared-db.connected',
    'identity-service.connected',
    'config.changed',
    'update-status',
    'upgrade-charm',
    'certificates.available',
)


@reactive.when_any('neutron-openvswitch.connected',
                   'ovsdb-subordinate.available')
def sdn_joined():
    reactive.set_flag('sdn-subordinate.connected')
    reactive.set_flag('sdn-subordinate.available')


@reactive.when_none('neutron-openvswitch.connected',
                    'ovsdb-subordinate.available')
def sdn_broken():
    reactive.clear_flag('sdn-subordinate.available')
    reactive.clear_flag('sdn-subordinate.connected')


@reactive.when_not('ovsdb-subordinate.available')
def disable_ovn_driver():
    reactive.clear_flag('charm.octavia.enable-ovn-driver')


@reactive.when('ovsdb-subordinate.available')
def maybe_enable_ovn_driver():
    ovsdb = reactive.endpoint_from_flag('ovsdb-subordinate.available')
    if ovsdb.ovn_configured:
        reactive.set_flag('charm.octavia.enable-ovn-driver')
        with charm.provide_charm_instance() as charm_instance:
            charm_instance.install()
            charm_instance.assess_status()


@reactive.when('identity-service.connected')
def setup_endpoint_connection(keystone):
    """Custom register endpoint function for Octavia.

    Octavia expects end users to have specifc roles assigned for access to the
    load-balancer API [0].  Create these roles on charm deployment / upgrade.

    0: https://docs.openstack.org/octavia/latest/configuration/policy.html
    """
    with charm.provide_charm_instance() as instance:
        keystone.register_endpoints(instance.service_type,
                                    instance.region,
                                    instance.public_url,
                                    instance.internal_url,
                                    instance.admin_url,
                                    requested_roles=octavia.OCTAVIA_ROLES)
        instance.assess_status()


@reactive.when('leadership.is_leader')
@reactive.when_not('leadership.set.heartbeat-key')
def generate_heartbeat_key():
    """Generate a unique key for ``heartbeat_key`` configuration option."""
    leadership.leader_set({'heartbeat-key': str(uuid.uuid4())})


@reactive.when('neutron-api.available')
def setup_neutron_lbaas_proxy():
    """Publish our URL to Neutron API units.

    The Neutron API unit will use this information to set up the
    ``lbaasv2-proxy`` service_plugin.

    This is to help migrate workloads expecting to talk to the Neutron API for
    their Load Balancing needs.

    Software should be updated to look up load balancer in the Keystone service
    catalog and talk directly to the Octavia endpoint.
    """
    neutron = reactive.endpoint_from_flag('neutron-api.available')
    with charm.provide_charm_instance() as octavia_charm:
        octavia_url = '{}:{}'.format(
            os_ip.canonical_url(endpoint_type=os_ip.INTERNAL),
            octavia_charm.api_port('octavia-api'))
        neutron.publish_load_balancer_info('octavia', octavia_url)


@reactive.when('identity-service.available')
@reactive.when('neutron-api.available')
@reactive.when('sdn-subordinate.available')
# Neutron API calls will consistently fail as long as AMQP is unavailable
@reactive.when('amqp.available')
def setup_hm_port():
    """Create a per unit Neutron and OVS port for Octavia Health Manager.

    This is used to plug the unit into the overlay network for direct
    communication with the octavia managed load balancer instances running
    within the deployed cloud.
    """
    neutron_ovs = reactive.endpoint_from_flag('neutron-openvswitch.connected')
    ovsdb = reactive.endpoint_from_flag('ovsdb-subordinate.available')
    host_id = neutron_ovs.host() if neutron_ovs else ovsdb.chassis_name
    with charm.provide_charm_instance() as octavia_charm:
        identity_service = reactive.endpoint_from_flag(
            'identity-service.available')
        try:
            if api_crud.setup_hm_port(
                    identity_service,
                    octavia_charm,
                    host_id=host_id):
                # trigger config render to make systemd-networkd bring up
                # automatic IP configuration of the new port right now.
                reactive.set_flag('config.changed')
        except api_crud.APIUnavailable as e:
            ch_core.hookenv.log('Neutron API not available yet, deferring '
                                'port discovery. ("{}")'
                                .format(e),
                                level=ch_core.hookenv.DEBUG)
            return


@reactive.when('leadership.is_leader')
@reactive.when('identity-service.available')
@reactive.when('neutron-api.available')
# Neutron API calls will consistently fail as long as AMQP is unavailable
@reactive.when('amqp.available')
def update_controller_ip_port_list():
    """Load state from Neutron and update ``controller-ip-port-list``."""
    identity_service = reactive.endpoint_from_flag(
        'identity-service.available')
    leader_ip_list = leadership.leader_get('controller-ip-port-list') or []

    try:
        neutron_ip_list = sorted(api_crud.get_port_ips(identity_service))
    except api_crud.APIUnavailable as e:
        ch_core.hookenv.log('Neutron API not available yet, deferring '
                            'port discovery. ("{}")'
                            .format(e),
                            level=ch_core.hookenv.DEBUG)
        return
    if neutron_ip_list != sorted(leader_ip_list):
        leadership.leader_set(
            {'controller-ip-port-list': json.dumps(neutron_ip_list)})


@reactive.when('shared-db.available')
@reactive.when('identity-service.available')
@reactive.when('amqp.available')
@reactive.when('leadership.set.heartbeat-key')
def render(*args):
    """Render the configuration for Octavia when all interfaces are available.
    """
    amp_key_name = ch_core.hookenv.config('amp-ssh-key-name')
    if amp_key_name:
        identity_service = reactive.endpoint_from_flag(
            'identity-service.available')
        api_crud.create_nova_keypair(identity_service, amp_key_name)

    with charm.provide_charm_instance() as octavia_charm:
        octavia_charm.render_with_interfaces(
            charm.optional_interfaces(
                args,
                'ovsdb-subordinate.available',
                'ovsdb-cms.available',
            ))
        octavia_charm.configure_ssl()
        octavia_charm.enable_webserver_site()
        octavia_charm.assess_status()
    reactive.set_state('config.rendered')


@reactive.when_not('db.synced')
@reactive.when('config.rendered')
def init_db():
    """Run initial DB migrations when config is rendered."""
    with charm.provide_charm_instance() as octavia_charm:
        octavia_charm.db_sync()
        octavia_charm.restart_all()
        reactive.set_state('db.synced')
        octavia_charm.assess_status()


@reactive.when('ha.connected')
@reactive.when_not('ha.available')
def cluster_connected(hacluster):
    """Configure HA resources in corosync."""
    with charm.provide_charm_instance() as octavia_charm:
        octavia_charm.configure_ha_resources(hacluster)
        octavia_charm.assess_status()
