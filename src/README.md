# Overview

This charm provides the Octavia load balancer service for an OpenStack Cloud.

OpenStack Rocky or later is required.

# Usage

Octavia and the Octavia charm relies on services from a fully functional
OpenStack Cloud and expects to be able to consume images from glance, create
networks in Neutron, consume certificate secrets from Barbican (preferably
utilizing a Vault backend) and spin up instances with Nova.

There is a [overlay bundle](https://github.com/openstack-charmers/openstack-bundles/blob/master/stable/overlays/loadbalancer-octavia.yaml)
to be used in conjunction with the [OpenStack Base bundle](https://jujucharms.com/openstack-base/).

Please refer to the [Octavia LBaaS](https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-octavia.html)
section of the [OpenStack Charms Deployment Guide](https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/index.html).

## Provider drivers

Octavia supports multiple provider drivers. The end user of the LBAASv2 API
may choose from the available provider drivers when creating a load balancer.

### Amphora provider

The reference Amphora provider driver is distributed as part of the Octavia
software, and is enabled by default, unless the `enable-amphora` configuration
option is set to 'False'.

The Amphora driver provides advanced features such as TLS termination, L7
loadbalancing and so on.

#### Amphora provider - Required configuration

After the deployment is complete and has settled, you must run the
`configure-resources` action on the lead unit. This will prompt it to configure
required resources in the deployed cloud for Octavia to operate. You must also
configure certificates for internal communication between the controller and
its load balancer instances.

Excerpt from the upstream
[operator maintenance guide](https://docs.openstack.org/octavia/latest/admin/guides/operator-maintenance.html#rotating-cryptographic-certificates):

> Octavia secures the communication between the amphora agent and the control
> plane with two-way SSL encryption. To accomplish that, several certificates
> are distributed in the system:
>
> * Control plane:
>   * Amphora certificate authority (CA) certificate: Used to validate amphora
>     certificates if Octavia acts as a Certificate Authority to issue new
>     amphora certificates
>   * Client certificate: Used to authenticate with the amphora
> * Amphora:
>   * Client CA certificate: Used to validate control plane client certificate
>   * Amphora certificate: Presented to control plane processes to prove
>     amphora identity.

The charm represents this with the following mandatory configuration options:

- `lb-mgmt-issuing-cacert`
- `lb-mgmt-issuing-ca-private-key`
- `lb-mgmt-issuing-ca-key-passphrase`
- `lb-mgmt-controller-cacert`
- `lb-mgmt-controller-cert`

You must issue/request certificates that meets your organizations requirements.

> **Note**: It is important not to use the same CA certificate for both
  `lb-mgmt-issuing-cacert` and `lb-mgmt-controller-cacert` configuration
  options.  Failing to keep them separate may lead to abuse of certificate data
  to gain access to other ``Amphora`` instances in the event one of them is
  compromised.

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
        lb-mgmt-issuing-cacert="$(base64 issuing_ca.pem)" \
        lb-mgmt-issuing-ca-private-key="$(base64 issuing_ca_key.pem)" \
        lb-mgmt-issuing-ca-key-passphrase=foobar \
        lb-mgmt-controller-cacert="$(base64 controller_ca.pem)" \
        lb-mgmt-controller-cert="$(base64 controller_cert_bundle.pem)"

#### Amphora provider - Optional resource configuration

By executing the `configure-resources` action the charm will create the
resources required for operation of the Octavia service.  If you want to manage
these resources yourself you must set the `create-mgmt-network` configuration
option to False.

You can at any time use the `configure-resources` action to prompt immediate
resource discovery.

To let the charm discover the resources and apply the appropriate configuration
to Octavia, you must use
[Neutron resource tags](https://docs.openstack.org/neutron/latest/contributor/internals/tag.html).

The UUID of the Nova flavor you want to use must be set with the
`custom-amp-flavor-id` configuration option.

| Resource type             | Tag                  | Description                                               |
| ------------------------- | -------------------- | --------------------------------------------------------- |
| Neutron Network           | charm-octavia        | Management network                                        |
| Neutron Subnet            | charm-octavia        | Management network subnet                                 |
| Neutron Router            | charm-octavia        | (Optional) Router for IPv6 RA or north/south mgmt traffic |
| Amphora Security Group    | charm-octavia        | Security group for Amphora ports                          |
| Controller Security Group | charm-octavia-health | Security group for Controller ports                       |

### OVN provider

When Octavia is deployed with OVN as SDN, a optional OVN provider driver is
enabled. If the `enable-amphora` configuration option is set to 'False' it
will be the only provider driver available.

> **Note**: The Amphora provider driver is still available and is the default
            even if you deploy with OVN as SDN. You may optionally disable the
            Amphora provider driver by setting the `enable-amphora`
            configuration option to 'False'.

#### OVN provider - Advantages

The OVN Provider driver has a few advantages when used as a provider driver
for Octavia over Amphora, like:

* OVN can be deployed without VMs, so there is no additional overhead as is
  required currently in Octavia when using the default Amphora driver.

* OVN Load Balancers can be deployed faster than default Load Balancers in
  Octavia (which use Amphora currently) because of no additional deployment requirement.

#### OVN provider - Limitations

OVN has its own set of limitations when considered as an Load Balancer driver. These include:

* OVN currently supports TCP and UDP, so Layer-7 based load balancing is not
  possible with the OVN provider driver.

* While Health Checks are now available in OVN, they are not currently
  implemented in OVN’s Provider Driver for Octavia.

* Currently, the OVN Provider driver supports a 1:1 protocol mapping between
  Listeners and associated Pools, i.e. a Listener which can handle TCP
  protocols can only be used with pools associated to the TCP protocol. Pools
  handling UDP protocols cannot be linked with TCP based Listeners.

  This limitation will be handled in an upcoming core OVN release.

* Mixed IPv4 and IPv6 members are not supported.

* Only the 'SOURCE_IP_PORT' load balancing algorithm is supported, others like
  'ROUND_ROBIN' and 'LEAST_CONNECTIONS' are not currently supported.

* Octavia flavors are not supported.

## Policy Overrides

Policy overrides is an **advanced** feature that allows an operator to override
the default policy of an OpenStack service. The policies that the service
supports, the defaults it implements in its code, and the defaults that a charm
may include should all be clearly understood before proceeding.

> **Caution**: It is possible to break the system (for tenants and other
  services) if policies are incorrectly applied to the service.

Policy statements are placed in a YAML file. This file (or files) is then (ZIP)
compressed into a single file and used as an application resource. The override
is then enabled via a Boolean charm option.

Here are the essential commands (filenames are arbitrary):

    zip overrides.zip override-file.yaml
    juju attach-resource octavia policyd-override=overrides.zip
    juju config octavia use-policyd-override=true

See appendix [Policy Overrides][cdg-appendix-n] in the [OpenStack Charms
Deployment Guide][cdg] for a thorough treatment of this feature.

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-octavia].

For general charm questions refer to the OpenStack [Charm Guide][cg].

<!-- LINKS -->

[cg]: https://docs.openstack.org/charm-guide
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide
[cdg-appendix-n]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-policy-overrides.html
[lp-bugs-charm-octavia]: https://bugs.launchpad.net/charm-octavia/+filebug
