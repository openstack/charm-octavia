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

import mock

import charms_openstack.test_utils as test_utils

import charm.openstack.api_crud as api_crud


class TestAPICrud(test_utils.PatchHelper):

    def test_session_from_identity_service(self):
        self.patch_object(api_crud, 'keystone_identity')
        self.patch_object(api_crud, 'keystone_session')
        identity_service = mock.MagicMock()
        result = api_crud.session_from_identity_service(identity_service)
        self.keystone_identity.Password.assert_called_once_with(
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
        self.keystone_session.Session.assert_called_once_with(
            auth=self.keystone_identity.Password())
        self.assertEqual(result, self.keystone_session.Session())

    def test_get_nova_flavor(self):
        self.patch_object(api_crud, 'nova_client')
        self.patch_object(api_crud, 'keystone_session')
        self.patch_object(api_crud, 'keystone_identity')
        self.patch_object(api_crud, 'keystone_exceptions')
        nova = mock.MagicMock()
        flavor = mock.MagicMock()
        flavor.id = 'fake-id'
        flavor.name = 'charm-octavia'
        nova.flavors.list.return_value = [flavor]
        self.nova_client.Client.return_value = nova

        self.keystone_exceptions.catalog.EndpointNotFound = Exception
        self.keystone_exceptions.connection.ConnectFailure = Exception
        self.nova_client.exceptions.ConnectionRefused = Exception
        self.nova_client.exceptions.ClientException = Exception
        nova.flavors.list.side_effect = Exception
        identity_service = mock.MagicMock()
        with self.assertRaises(api_crud.APIUnavailable):
            api_crud.get_nova_flavor(identity_service)

        nova.flavors.list.side_effect = None
        api_crud.get_nova_flavor(identity_service)
        self.nova_client.Client.assert_called_with(
            '2',
            session=self.keystone_session.Session(auth=self.keystone_identity))
        nova.flavors.list.assert_called_with(is_public=False)
        self.assertFalse(nova.flavors.create.called)
        nova.flavors.list.return_value = []
        nova.flavors.create.return_value = flavor
        api_crud.get_nova_flavor(identity_service)
        nova.flavors.create.assert_called_with('charm-octavia', 1024, 1, 8,
                                               is_public=False)
