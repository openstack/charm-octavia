#!/usr/local/sbin/charm-env python3
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

import os
import sys

# Load modules from $CHARM_DIR/lib
sys.path.append('lib')
sys.path.append('reactive')

from charms.layer import basic
basic.bootstrap_charm_deps()
basic.init_config_states()

import charms.reactive as reactive
import charms.leadership as leadership

import charms_openstack.bus
import charms_openstack.charm as charm

import charmhelpers.core as ch_core

import charm.openstack.api_crud as api_crud

charms_openstack.bus.discover()


def configure_resources(*args):
    """Create/discover resources for management of load balancer instances."""
    if not reactive.is_flag_set('leadership.is_leader'):
        return ch_core.hookenv.action_fail('action must be run on the leader '
                                           'unit.')
    if not reactive.all_flags_set('identity-service.available',
                                  'neutron-api.available',
                                  'sdn-subordinate.available',
                                  'amqp.available'):
        return ch_core.hookenv.action_fail('all required relations not '
                                           'available, please defer action'
                                           'until deployment is complete.')
    identity_service = reactive.endpoint_from_flag(
        'identity-service.available')
    try:
        (network, secgrp) = api_crud.get_mgmt_network(
            identity_service,
            create=reactive.is_flag_set('config.default.create-mgmt-network'),
        )
    except api_crud.APIUnavailable as e:
        ch_core.hookenv.action_fail('Neutron API not available yet, deferring '
                                    'network creation/discovery. ("{}")'
                                    .format(e))
        return
    if network and secgrp:
        leadership.leader_set({'amp-boot-network-list': network['id'],
                               'amp-secgroup-list': secgrp['id']})
    if reactive.is_flag_set('config.default.custom-amp-flavor-id'):
        # NOTE(fnordahl): custom flavor provided through configuration is
        # handled in the charm class configuration property.
        try:
            flavor = api_crud.get_nova_flavor(identity_service)
        except api_crud.APIUnavailable as e:
            ch_core.hookenv.action_fail('Nova API not available yet, '
                                        'deferring flavor '
                                        'creation. ("{}")'
                                        .format(e))
            return
        else:
            leadership.leader_set({'amp-flavor-id': flavor.id})

    amp_key_name = ch_core.hookenv.config('amp-ssh-key-name')
    if amp_key_name:
        identity_service = reactive.endpoint_from_flag(
            'identity-service.available')
        api_crud.create_nova_keypair(identity_service, amp_key_name)

    # execute port setup for leader, the followers will execute theirs on
    # `leader-settings-changed` hook
    with charm.provide_charm_instance() as octavia_charm:
        api_crud.setup_hm_port(identity_service, octavia_charm)
        octavia_charm.render_all_configs()
        octavia_charm._assess_status()


ACTIONS = {
    'configure-resources': configure_resources,
}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return 'Action {} undefined'.format(action_name)
    else:
        try:
            action(args)
        except Exception as e:
            ch_core.hookenv.action_fail(str(e))


if __name__ == '__main__':
    sys.exit(main(sys.argv))
