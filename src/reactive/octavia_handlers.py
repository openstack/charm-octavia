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

import uuid

import charms.reactive as reactive
import charms.leadership as leadership

import charms_openstack.charm as charm

import charm.openstack.octavia as octavia  # noqa

charm.use_defaults(
    'charm.installed',
    'amqp.connected',
    'shared-db.connected',
    'identity-service.connected',
    'identity-service.available',
    'config.changed',
    'update-status')


@reactive.when('leadership.is_leader')
@reactive.when_not('leadership.set.heartbeat-key')
def generate_heartbeat_key():
    """Generate a unique key for ``heartbeat_key`` configuration option."""
    leadership.leader_set({'heartbeat-key': str(uuid.uuid4())})


@reactive.when('shared-db.available')
@reactive.when('identity-service.available')
@reactive.when('amqp.available')
@reactive.when('leadership.set.heartbeat-key')
def render(*args):
    """
    Render the configuration for Octavia when all interfaces are available.
    """
    with charm.provide_charm_instance() as octavia_charm:
        octavia_charm.render_with_interfaces(args)
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
