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

import base64
import collections
import os
import subprocess

import charms_openstack.charm
import charms_openstack.adapters
import charms_openstack.ip as os_ip

import charms.leadership as leadership

import charmhelpers.core as ch_core

OCTAVIA_DIR = '/etc/octavia'
OCTAVIA_CACERT_DIR = os.path.join(OCTAVIA_DIR, 'certs')
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


@charms_openstack.adapters.config_property
def issuing_cacert(cls):
    """Get path to certificate provided in ``lb-mgmt-issuing-cacert`` option.

    Side effect of reading this property is that the on-disk certificate
    data is updated if it has changed.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    """
    config = ch_core.hookenv.config('lb-mgmt-issuing-cacert')
    if config:
        return cls.charm_instance.decode_and_write_cert(
            'issuing_ca.pem',
            config)


@charms_openstack.adapters.config_property
def issuing_ca_private_key(cls):
    """Get path to key provided in ``lb-mgmt-issuing-ca-private-key`` option.

    Side effect of reading this property is that the on-disk key
    data is updated if it has changed.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    """
    config = ch_core.hookenv.config('lb-mgmt-issuing-ca-private-key')
    if config:
        return cls.charm_instance.decode_and_write_cert(
            'issuing_ca_key.pem',
            config)


@charms_openstack.adapters.config_property
def issuing_ca_private_key_passphrase(cls):
    """Get value provided in in ``lb-mgmt-issuing-ca-key-passphrase`` option.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    """
    config = ch_core.hookenv.config('lb-mgmt-issuing-ca-key-passphrase')
    if config:
        return config


@charms_openstack.adapters.config_property
def controller_cacert(cls):
    """Get path to certificate provided in ``lb-mgmt-controller-cacert`` opt.

    Side effect of reading this property is that the on-disk certificate
    data is updated if it has changed.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    """
    config = ch_core.hookenv.config('lb-mgmt-controller-cacert')
    if config:
        return cls.charm_instance.decode_and_write_cert(
            'controller_ca.pem',
            config)


@charms_openstack.adapters.config_property
def controller_cert(cls):
    """Get path to certificate provided in ``lb-mgmt-controller-cert`` option.

    Side effect of reading this property is that the on-disk certificate
    data is updated if it has changed.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    """
    config = ch_core.hookenv.config('lb-mgmt-controller-cert')
    if config:
        return cls.charm_instance.decode_and_write_cert(
            'controller_cert.pem',
            config)


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
                ch_core.host.service_reload('apache2',
                                            restart_on_failure=True)

    def decode_and_write_cert(self, filename, encoded_data):
        """Write certificate data to disk.

        :param filename: Name of file
        :type filename: str
        :param group: Group ownership
        :type group: str
        :param encoded_data: Base64 encoded data
        :type encoded_data: str
        :returns: Full path to file
        :rtype: str
        """
        filename = os.path.join(OCTAVIA_CACERT_DIR, filename)
        ch_core.host.mkdir(OCTAVIA_CACERT_DIR, group=self.group,
                           perms=0o750)
        ch_core.host.write_file(filename, base64.b64decode(encoded_data),
                                group=self.group, perms=0o440)
        return filename

    @charms_openstack.adapters.config_property
    def heartbeat_key(self):
        return leadership.leader_get('heartbeat-key')
