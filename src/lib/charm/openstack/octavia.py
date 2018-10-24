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

import collections
import os
import subprocess

import charms_openstack.charm
import charms_openstack.adapters
import charms_openstack.ip as os_ip

import charms.leadership as leadership

import charmhelpers.core.host as ch_host

OCTAVIA_DIR = '/etc/octavia'
OCTAVIA_CONF = os.path.join(OCTAVIA_DIR, 'octavia.conf')
OCTAVIA_WEBSERVER_SITE = 'octavia-api'
OCTAVIA_WSGI_CONF = '/etc/apache2/sites-available/octavia-api.conf'

charms_openstack.charm.use_defaults('charm.default-select-release')


class OctaviaAdapters(charms_openstack.adapters.OpenStackAPIRelationAdapters):
    """Adapters class for the Octavia charm."""
    def __init__(self, relations, charm_instance=None):
        super(OctaviaAdapters, self).__init__(
            relations,
            options_instance=charms_openstack.adapters.APIConfigurationAdapter(
                service_name='octavia',
                port_map=OctaviaCharm.api_ports),
            charm_intance=charm_instance)


class OctaviaCharm(charms_openstack.charm.HAOpenStackCharm):
    """Charm class for the Octavia charm."""
    # layer-openstack-api uses service_type as service name in endpoint catalog
    service_type = 'octavia'
    release = 'rocky'
    packages = ['octavia-api', 'octavia-health-manager',
                'octavia-housekeeping', 'octavia-worker',
                'apache2', 'libapache2-mod-wsgi-py3']
    python_version = 3
    api_ports = {
        'octavia-api': {
            os_ip.PUBLIC: 9876,
            os_ip.ADMIN: 9876,
            os_ip.INTERNAL: 9876,
        },
    }
    default_service = 'octavia-api'
    services = ['apache2', 'octavia-health-manager', 'octavia-housekeeping',
                'octavia-worker']
    required_relations = ['shared-db', 'amqp', 'identity-service']
    restart_map = {
        OCTAVIA_CONF: services,
        OCTAVIA_WSGI_CONF: ['apache2'],
    }
    sync_cmd = ['sudo', 'octavia-db-manage', 'upgrade', 'head']
    ha_resources = ['vips', 'haproxy', 'dnsha']
    release_pkg = 'octavia-common'
    package_codenames = {
        'octavia-common': collections.OrderedDict([
            ('1', 'rocky'),
        ]),
    }
    group = 'octavia'

    def get_amqp_credentials(self):
        """Configure the AMQP credentials for Octavia."""
        return ('octavia', 'openstack')

    def get_database_setup(self):
        """Configure the database credentials for Octavia."""
        return [{'database': 'octavia',
                 'username': 'octavia'}]

    def enable_webserver_site(self):
        """Enable Octavia API apache2 site if rendered or installed"""
        if os.path.exists(OCTAVIA_WSGI_CONF):
            check_enabled = subprocess.call(
                ['a2query', '-s', OCTAVIA_WEBSERVER_SITE]
            )
            if check_enabled != 0:
                subprocess.check_call(['a2ensite',
                                       OCTAVIA_WEBSERVER_SITE])
                ch_host.service_reload('apache2',
                                       restart_on_failure=True)

    @charms_openstack.adapters.config_property
    def heartbeat_key(self):
        return leadership.leader_get('heartbeat-key')
