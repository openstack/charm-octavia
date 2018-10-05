# Overview

This charm provides the Octavia load balancer service for an OpenStack Cloud.

# Usage

Octavia relies on services from a fully functional OpenStack Cloud and expects
to be able to add images to glance, create networks in Neutron, store
certificate secrets in Vault (optionally) and spin up instances with Nova.

    juju deploy octavia --config openstack-origin=bionic:rocky
    juju add-relation octavia rabbitmq-server
    juju add-relation octavia mysql
    juju add-relation octavia keystone
    juju add-relation octavia vault

# Bugs

Please report bugs on [Launchpad](https://bugs.launchpad.net/charm-octavia/+filebug).

For general questions please refer to the OpenStack [Charm Guide](https://docs.openstack.org/charm-guide/latest/).
