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
import json
import os
import subprocess

import charms_openstack.charm
import charms_openstack.adapters
import charms_openstack.ip as os_ip
import charms_openstack.plugins as ch_plugins

import charms.leadership as leadership
import charms.reactive as reactive

import charmhelpers.core as ch_core
import charmhelpers.contrib.charmsupport.nrpe as ch_nrpe
import charmhelpers.contrib.network.ip as ch_net_ip

OCTAVIA_DIR = '/etc/octavia'
OCTAVIA_CACERT_DIR = os.path.join(OCTAVIA_DIR, 'certs')
OCTAVIA_CONF = os.path.join(OCTAVIA_DIR, 'octavia.conf')
OCTAVIA_WEBSERVER_SITE = 'octavia-api'
OCTAVIA_WSGI_CONF = '/etc/apache2/sites-available/octavia-api.conf'

OCTAVIA_INT_BRIDGE = 'br-int'
OCTAVIA_MGMT_INTF = 'o-hm0'
OCTAVIA_MGMT_INTF_CONF = ('/etc/systemd/network/99-charm-octavia-{}.network'
                          .format(OCTAVIA_MGMT_INTF))
OCTAVIA_MGMT_NAME_PREFIX = 'lb-mgmt'
OCTAVIA_MGMT_NET = OCTAVIA_MGMT_NAME_PREFIX + '-net'
OCTAVIA_MGMT_SUBNET = OCTAVIA_MGMT_NAME_PREFIX + '-subnet'
OCTAVIA_MGMT_SECGRP = OCTAVIA_MGMT_NAME_PREFIX + '-sec-grp'
OCTAVIA_HEALTH_SECGRP = 'lb-health-mgr-sec-grp'
OCTAVIA_HEALTH_LISTEN_PORT = '5555'

OCTAVIA_ROLES = [
    'load-balancer_observer',
    'load-balancer_global_observer',
    'load-balancer_member',
    'load-balancer_quota_admin',
    'load-balancer_admin',
]

NAGIOS_PLUGINS = '/usr/local/lib/nagios/plugins'

# config.changed is needed to get the policyd override clean-up to work when
# setting use-policyd-override=false
charms_openstack.charm.use_defaults('charm.default-select-release',
                                    'config.changed')


def get_address_on_mgmt_interface():
    """
    Check for an address assigned to the managament interface and return it.

    Follow the same logic as used by health_manager_bind_ip(),
    since that's the reason we need to check for an address.

    :returns: the address if an address was found, otherwise None
    :rtype: Optional[str]
    """
    for af in ['AF_INET6', 'AF_INET']:
        try:
            ips = ch_net_ip.get_iface_addr(
                iface=OCTAVIA_MGMT_INTF, inet_type=af
            )
            ch_core.hookenv.log(
                'Checking for address on mgmt interface; '
                'found these IPs on {} ({}): {}'.format(
                    OCTAVIA_MGMT_INTF, af, ips,
                ),
                level=ch_core.hookenv.DEBUG,
            )

            ips = [ip for ip in ips if '%' not in ip]
            if ips:
                ch_core.hookenv.log(
                    'Returning address found on mgmt interface: {}'.format(
                        ips[0],
                    ),
                    level=ch_core.hookenv.DEBUG,
                )
                return ips[0]
        except Exception as e:
            # ch_net_ip.get_iface_addr() throws an exception of type
            # Exception when the requested interface does not exist or if
            # it has no addresses in the requested address family.
            ch_core.hookenv.log(
                'Checking for address on mgmt interface failed: {}'.format(e),
                level=ch_core.hookenv.DEBUG,
            )
            pass

    return None


@charms_openstack.adapters.config_property
def health_manager_hwaddr(cls):
    """Return hardware address for Health Manager interface.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    :returns: hardware address for unit local Health Manager interface.
    :rtype: str
    """
    try:
        external_ids = json.loads(
            subprocess.check_output(['ovs-vsctl', 'get', 'Interface',
                                     OCTAVIA_MGMT_INTF,
                                     'external_ids:attached-mac'],
                                    universal_newlines=True))
    except (subprocess.CalledProcessError, OSError) as e:
        ch_core.hookenv.log('Unable query OVS, not ready? ("{}")'
                            .format(e),
                            level=ch_core.hookenv.DEBUG)
        return
    return external_ids


@charms_openstack.adapters.config_property
def health_manager_bind_ip(cls):
    """IP address health manager process should bind to.

    The value is configured individually per unit and reflects the IP
    address assigned to the specific units tunnel port.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    :returns: IP address of unit local Health Manager interface.
    :rtype: str
    """
    ip = get_address_on_mgmt_interface()
    if ip:
        return ip

    # we should only get to here if setup_hm_port has failed
    # or never been called.
    # because that function should create the interface
    # that we're querying above.
    ch_core.hookenv.log(
        'health_manager_bind_ip failed to discover any addresses',
        level=ch_core.hookenv.WARNING
    )


@charms_openstack.adapters.config_property
def heartbeat_key(cls):
    """Key used to validate Amphorae heartbeat messages.

    The value is generated by the charm and is shared among all units
    through leader storage.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    :returns: Key as retrieved from Juju leader storage.
    :rtype: str
    """
    return leadership.leader_get('heartbeat-key')


@charms_openstack.adapters.config_property
def controller_ip_port_list(cls):
    """List of ip:port pairs for Amphorae instances health reporting.

    The list is built based on information from individual Octavia units
    coordinated, stored and shared among all units trhough leader storage.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    :returns: Comma separated list of ip:port pairs.
    :rtype: str
    """
    try:
        ip_list = json.loads(
            leadership.leader_get('controller-ip-port-list'))
    except TypeError:
        return
    if ip_list:
        port_suffix = ':' + OCTAVIA_HEALTH_LISTEN_PORT
        return (port_suffix + ', ').join(sorted(ip_list)) + port_suffix


@charms_openstack.adapters.config_property
def amp_secgroup_list(cls):
    """List of security groups to attach to Amphorae instances.

    The list is built from IDs of charm managed security groups shared
    among all units through leader storage.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    :returns: Comma separated list of Neutron security group UUIDs.
    :rtype: str
    """
    return leadership.leader_get('amp-secgroup-list')


@charms_openstack.adapters.config_property
def amp_boot_network_list(cls):
    """Networks to attach when creating Amphorae instances.

    IDs from charm managed networks shared among all units through leader
    storage.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    :returns: Comma separated list of Neutron network UUIDs.
    :rtype: str
    """
    return leadership.leader_get('amp-boot-network-list')


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
            config,
            check=False
        )


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


@charms_openstack.adapters.config_property
def amp_flavor_id(cls):
    """Flavor to use when creating Amphorae instances.

    ID from charm managed flavor shared among all units through leader
    storage.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    :returns: Nova flavor UUID.
    :rtype: str
    """
    return (
        ch_core.hookenv.config('custom-amp-flavor-id') or
        leadership.leader_get('amp-flavor-id'))


@charms_openstack.adapters.config_property
def spare_amphora_pool_size(cls):
    """Number of spare Amphora instances to pool

    Octavia can maintain a pool of Amphora instance to reduce the spin up
    time for new loadbalancer services.

    :param cls: charms_openstack.adapters.ConfigurationAdapter derived class
                instance.  Charm class instance is at cls.charm_instance.
    :type: cls: charms_openstack.adapters.ConfiguartionAdapter
    :returns: Number of amphora instances to pool.
    :rtype: str
    """
    return ch_core.hookenv.config('spare-pool-size')


# note plugin comes first to override the config_changed method as a mixin
class BaseOctaviaCharm(ch_plugins.PolicydOverridePlugin,
                       charms_openstack.charm.HAOpenStackCharm):
    """Base charm class for the Octavia charm."""
    abstract_class = True

    # layer-openstack-api uses service_type as service name in endpoint catalog
    name = service_type = 'octavia'
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
    required_relations = ['shared-db', 'amqp', 'identity-service',
                          'sdn-subordinate']
    sync_cmd = ['sudo', 'octavia-db-manage', 'upgrade', 'head']
    ha_resources = ['vips', 'haproxy', 'dnsha']
    release_pkg = 'octavia-common'
    package_codenames = {
        'octavia-common': collections.OrderedDict([
            ('1', 'rocky'),
            ('4', 'stein'),
            ('5', 'train'),
            ('6', 'ussuri'),
            ('7', 'victoria'),
        ]),
    }
    group = 'octavia'

    # policyd override constants
    policyd_service_name = 'octavia'
    policyd_restart_on_change = True

    @property
    def services(self):
        """Allow descendents to modify the service list."""
        return ['apache2', 'octavia-health-manager', 'octavia-housekeeping',
                'octavia-worker']

    @property
    def restart_map(self):
        """Allow descendents to modify the restart map."""
        return {
            OCTAVIA_MGMT_INTF_CONF: self.services + ['systemd-networkd'],
            OCTAVIA_CONF: self.services,
            OCTAVIA_WSGI_CONF: ['apache2'],
        }

    def install(self):
        """Custom install function.

        We need to add user `systemd-network` to `octavia` group so it can
        read the systemd-networkd config we write.

        We run octavia as a WSGI service and need to disable the `octavia-api`
        service in init system so it does not steal the port from haproxy /
        apache2.
        """
        super().install()
        ch_core.host.add_user_to_group('systemd-network', 'octavia')
        ch_core.host.service_pause('octavia-api')

    def states_to_check(self, required_relations=None):
        """Custom state check function for charm specific state check needs.

        Interface used for ``neutron_openvswitch`` subordinate lacks a
        ``available`` state.

        The ``Octavia`` service will not operate normally until Nova and
        Neutron resources have been created, this needs to be tracked in
        workload status.
        """
        states_to_check = super().states_to_check(required_relations)
        if not self.options.enable_amphora:
            # Amphora provider driver not enabled, custom checks not necessary
            return states_to_check
        if not leadership.leader_get('amp-boot-network-list'):
            if not reactive.is_flag_set('config.default.create-mgmt-network'):
                # we are configured to not create required resources and they
                # are not present, prompt end-user to create them.
                states_to_check['crud'] = [
                    ('crud.available',  # imaginate ``crud`` relation
                     'blocked',
                     'Awaiting end-user to create required resources and '
                     'execute `configure-resources` action')]
            else:
                if reactive.is_flag_set('leadership.is_leader'):
                    who = 'end-user execution of `configure-resources` action'
                else:
                    who = 'leader'
                states_to_check['crud'] = [
                    ('crud.available',  # imaginate ``crud`` relation
                     'blocked',
                     'Awaiting {} to create required resources'.format(who))]
        else:
            states_to_check['octavia'] = [
                ('octavia.hm-port.available',
                 'blocked',
                 'Virtual network for access to Amphorae is down')]
        # if these configuration options are at default value it means they are
        # not set by end-user, they are required for successfull creation of
        # load balancer instances.
        if (reactive.is_flag_set('config.default.lb-mgmt-issuing-cacert') or
                reactive.is_flag_set(
                    'config.default.lb-mgmt-issuing-ca-private-key') or
                reactive.is_flag_set(
                    'config.default.lb-mgmt-issuing-ca-key-passphrase') or
                reactive.is_flag_set(
                'config.default.lb-mgmt-controller-cacert') or
                reactive.is_flag_set(
                    'config.default.lb-mgmt-controller-cert')):
            # set workload status to prompt end-user attention
            states_to_check['config'] = [
                ('config._required_certs',  # imaginate flag
                 'blocked',
                 'Missing required certificate configuration, please '
                 'examine documentation')]
        return states_to_check

    def custom_assess_status_last_check(self):
        """Add extra status checks.

        This is called by the base charm class assess_status handler,
        after all other checks.

        This is a good place to put additional information about the running
        service, such as cluster status etc.

        Return (None, None) if the status is okay (i.e. the unit is active).
        Return ('active', message) do shortcut and force the unit to the active
        status.
        Return (other_status, message) to set the status to desired state.

        :returns: None, None - no action in this function.
        """
        if ch_core.hookenv.config('enable-amphora'):
            if not get_address_on_mgmt_interface():
                return ('blocked', 'no address on mgmt interface')
        return (None, None)

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

    def decode_and_write_cert(self, filename, encoded_data, check=True):
        """Write certificate data to disk.

        Side effect of writing a certificate is that an nrpe check is added
        to check validity and expiration of the certificate if `check=True` is
        passed.

        :param filename: Name of file
        :type filename: str
        :param encoded_data: Base64 encoded data
        :type encoded_data: str
        :param check: Install the nrpe check
        :type check: bool
        :returns: Full path to file
        :rtype: str
        """
        filename = os.path.join(OCTAVIA_CACERT_DIR, filename)
        ch_core.host.mkdir(OCTAVIA_CACERT_DIR, group=self.group,
                           perms=0o750)
        ch_core.host.write_file(filename, base64.b64decode(encoded_data),
                                group=self.group, perms=0o440)
        if check:
            check_cmd = '{} -C {},{} {}'.format(
                os.path.join(NAGIOS_PLUGINS, 'check_cert.py'),
                ch_core.hookenv.config('tls_crit_days'),
                ch_core.hookenv.config('tls_warn_days'),
                filename
            )
            description = 'Check Certificate %s' % os.path.basename(filename)

            nrpe = ch_nrpe.NRPE()
            nrpe.add_check(
                shortname='cert_%s' % os.path.basename(filename).split(".")[0],
                description=description,
                check_cmd=check_cmd
            )
            nrpe.write()
        return filename

    @property
    def local_address(self):
        """Return local address as provided by our ConfigurationClass."""
        return self.configuration_class().local_address

    @property
    def local_unit_name(self):
        """Return local unit name as provided by our ConfigurationClass."""
        return self.configuration_class().local_unit_name


class RockyOctaviaCharm(BaseOctaviaCharm):
    """Charm class for the Octavia charm on Rocky and newer releases."""
    release = 'rocky'


class VictoriaOctaviaCharm(BaseOctaviaCharm):
    """Charm class for the Octavia charm on Ussuri and newer releases."""
    release = 'victoria'

    @property
    def all_packages(self):
        all_packages = super().all_packages
        # NOTE(fnordahl): We probably should have a more generic harness for
        # these kinds of extensions, there might be more SDNs that want support
        # in the charm.
        if reactive.is_flag_set('charm.octavia.enable-ovn-driver'):
            all_packages.extend([
                'octavia-driver-agent',
                'python3-ovn-octavia-provider'
            ])
        return all_packages

    @property
    def services(self):
        _services = super().services
        if reactive.is_flag_set('charm.octavia.enable-ovn-driver'):
            _services.extend(['octavia-driver-agent'])
        return _services

    @property
    def restart_map(self):
        _restart_map = super().restart_map
        if reactive.is_flag_set('charm.octavia.enable-ovn-driver'):
            _restart_map.update({
                os.path.join(OCTAVIA_DIR, 'ovn_ca_cert.pem'): [
                    'octavia-driver-agent'],
                os.path.join(OCTAVIA_DIR, 'ovn_certificate.pem'): [
                    'octavia-driver-agent'],
                os.path.join(OCTAVIA_DIR, 'ovn_private_key.pem'): [
                    'octavia-driver-agent'],
            })
        return _restart_map
