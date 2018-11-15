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

from keystoneauth1 import identity as keystone_identity
from keystoneauth1 import session as keystone_session
from keystoneauth1 import exceptions as keystone_exceptions
from novaclient import client as nova_client


class APIUnavailable(Exception):

    def __init__(self, service_type, resource_type, upstream_exception):
        self.service_type = service_type
        self.resource_type = resource_type
        self.upstream_exception = upstream_exception


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
    return keystone_session.Session(auth=auth)


def get_nova_flavor(identity_service):
    """Get or create private Nova flavor for use with Octavia.

    A side effect of calling this function is that Nova flavors are
    created if they do not already exist.

    Handle exceptions ourself without Tenacity so we can detect Nova API
    readiness.  At present we do not have a relation or interface to inform us
    about Nova API readiness.  This function also executes just one or two API
    calls.

    :param identity_service: reactive Endpoint of type ``identity-service``
    :type identity_service: RelationBase class
    :returns: Nova Flavor Resource object
    :rtype: novaclient.v2.flavors.Flavor
    """
    try:
        session = session_from_identity_service(identity_service)
        nova = nova_client.Client('2', session=session)
        flavors = nova.flavors.list(is_public=False)
        for flavor in flavors:
            if flavor.name == 'charm-octavia':
                return flavor

        # create flavor
        return nova.flavors.create('charm-octavia', 1024, 1, 8,
                                   is_public=False)
    except (keystone_exceptions.catalog.EndpointNotFound,
            keystone_exceptions.connection.ConnectFailure,
            nova_client.exceptions.ConnectionRefused,
            nova_client.exceptions.ClientException) as e:
        raise APIUnavailable('nova', 'flavors', e)
