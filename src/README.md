# Overview

This charm provides the Octavia load balancer service for an OpenStack Cloud.

OpenStack Rocky or later is required.

# Usage

Octavia and the Octavia charm relies on services from a fully functional OpenStack Cloud and expects to be able to consume images from glance, create networks in Neutron, consume certificate secrets from Barbican (preferably utilizing a Vault backend) and spin up instances with Nova.

There is a [overlay bundle](https://github.com/openstack-charmers/openstack-bundles/blob/master/stable/overlays/loadbalancer-octavia.yaml) to be used in conjunction with the [OpenStack Base bundle](https://jujucharms.com/openstack-base/).

Please refer to the [Octavia LBaaS](https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-octavia.html) section of the [OpenStack Charms Deployment Guide](https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/index.html)

## Required configuration

After the deployment is complete and has settled, you must run the `configure-resources` action on the lead unit.

This will prompt it to configure required resources in the deployed cloud for Octavia to operate.

You must also configure certificates for internal communication between the controller and its load balancer instances.

Excerpt from the upstream [operator maintenance guide](https://docs.openstack.org/octavia/latest/admin/guides/operator-maintenance.html#rotating-cryptographic-certificates):

> Octavia secures the communication between the amphora agent and the control plane with two-way SSL encryption. To accomplish that, several certificates are distributed in the system:
>
> * Control plane:
>   * Amphora certificate authority (CA) certificate: Used to validate amphora certificates if Octavia acts as a Certificate Authority to issue new amphora certificates
>   * Client certificate: Used to authenticate with the amphora
> * Amphora:
>   * Client CA certificate: Used to validate control plane client certificate
>   * Amphora certificate: Presented to control plane processes to prove amphora identity.

The charm represents this with the following mandatory configuration options:

- `lb-mgmt-issuing-cacert`

- `lb-mgmt-issuing-ca-private-key`

- `lb-mgmt-issuing-ca-key-passphrase`

- `lb-mgmt-controller-cacert`

- `lb-mgmt-controller-cert`

You must issue/request certificates that meets your organizations requirements.

__NOTE__ It is important not to use the same CA certificate for both `lb-mgmt-issuing-cacert` and `lb-mgmt-controller-cacert` configuration options.  Failing to keep them separate may lead to abuse of certificate data to gain access to other ``Amphora`` instances in the event one of them is compromised.

To get you started we include an example of generating your own certificates:

    mkdir -p demoCA/newcerts
    touch demoCA/index.txt
    touch demoCA/index.txt.attr
    openssl genrsa -passout pass:foobar -des3 -out issuing_ca_key.pem 2048
    openssl req -x509 -passin pass:foobar -new -nodes -key issuing_ca_key.pem \
        -config /etc/ssl/openssl.cnf \
        -subj "/C=US/ST=Somestate/O=Org/CN=www.example.com" \
        -days 30 \
        -out issuing_ca.pem

    openssl genrsa -passout pass:foobar -des3 -out controller_ca_key.pem 2048
    openssl req -x509 -passin pass:foobar -new -nodes \
            -key controller_ca_key.pem \
        -config /etc/ssl/openssl.cnf \
        -subj "/C=US/ST=Somestate/O=Org/CN=www.example.com" \
        -days 30 \
        -out controller_ca.pem
    openssl req \
        -newkey rsa:2048 -nodes -keyout controller_key.pem \
        -subj "/C=US/ST=Somestate/O=Org/CN=www.example.com" \
        -out controller.csr
    openssl ca -passin pass:foobar -config /etc/ssl/openssl.cnf \
        -cert controller_ca.pem -keyfile controller_ca_key.pem \
        -create_serial -batch \
        -in controller.csr -days 30 -out controller_cert.pem
    cat controller_cert.pem controller_key.pem > controller_cert_bundle.pem

To apply the configuration execute:

    juju config octavia \
        lb-mgmt-issuing-cacert="$(base64 controller_ca.pem)" \
        lb-mgmt-issuing-ca-private-key="$(base64 controller_ca_key.pem)" \
        lb-mgmt-issuing-ca-key-passphrase=foobar \
        lb-mgmt-controller-cacert="$(base64 controller_ca.pem)" \
        lb-mgmt-controller-cert="$(base64 controller_cert_bundle.pem)"

## Optional resource configuration

By executing the `configure-resources` action the charm will create the resources required for operation of the Octavia service.  If you want to manage these resources yourself you must set the `create-mgmt-network` configuration option to False.

You can at any time use the `configure-resources` action to prompt immediate resource discovery.

To let the charm discover the resources and apply the appropriate configuration
to Octavia, you must use [Neutron resource tags](https://docs.openstack.org/neutron/latest/contributor/internals/tag.html).

The UUID of the Nova flavor you want to use must be set with the
`custom-amp-flavor-id` configuration option.

| Resource type             | Tag                  | Description                                               |
| ------------------------- | -------------------- | --------------------------------------------------------- |
| Neutron Network           | charm-octavia        | Management network                                        |
| Neutron Subnet            | charm-octavia        | Management network subnet                                 |
| Neutron Router            | charm-octavia        | (Optional) Router for IPv6 RA or north/south mgmt traffic |
| `Amphora` Security Group  | charm-octavia        | Security group for Amphora ports                          |
| Controller Security Group | charm-octavia-health | Security group for Controller ports                       |

# Bugs

Please report bugs on [Launchpad](https://bugs.launchpad.net/charm-octavia/+filebug).

For general questions please refer to the OpenStack [Charm Guide](https://docs.openstack.org/charm-guide/latest/).
