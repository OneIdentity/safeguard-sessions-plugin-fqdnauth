#
#   Copyright (c) 2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from mock import patch
from textwrap import dedent
from copy import deepcopy
import pytest

from ..plugin import Plugin


def test_authentication_is_not_performed():
    result = Plugin(configuration="").do_authenticate()
    assert result['verdict'] == 'ACCEPT'


def test_target_ip_is_resolved():
    with patch('safeguard.sessions.plugin.host_resolver.HostResolver.resolve_hosts_by_ip') as mock_resolver:
        target_server = '1.2.3.4'
        Plugin(configuration="").authorize(
                    cookie={},
                    session_cookie={},
                    target_server=target_server,
                    target_username="test_user")
        mock_resolver.assert_called_once_with(target_server)


def provide_authorization_test_cases():
    yield pytest.param(
        {
            'target_ip_resolved': ['host1234'],
            'config': dedent("""
                [hosts_for_groups]
                __all__ = host1234
                """),
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': 'DONTCARE',
                'target_username': 'DONTCARE',
                'gateway_groups': []
            },
            'expected_verdict': 'ACCEPT'
        },
        id='Target IP resolved to one host in whitelist is accepted'
    )

    yield pytest.param(
        {
            'target_ip_resolved': ['different_host'],
            'config': dedent("""
                [hosts_for_groups]
                __all__ = host1234
                """),
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': 'DONTCARE',
                'target_username': 'DONTCARE',
                'gateway_groups': []
            },
            'expected_verdict': 'DENY'
        },
        id='Target IP resolved to one host not in whitelist is denied',
    )

    yield pytest.param(
        {
            'target_ip_resolved': ['host1234', 'different_host'],
            'config': dedent("""
                [hosts_for_groups]
                __all__ = host1234
                """),
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': 'DONTCARE',
                'target_username': 'DONTCARE',
                'gateway_groups': []
            },
            'expected_verdict': 'ACCEPT'
        },
        id='Target IP resolved to multiple hosts in whitelist is accepted',
    )

    yield pytest.param(
        {
            'target_ip_resolved': ['host1234'],
            'config': dedent("""[hosts_for_groups]\n__all__ = {whitelist}\n
                """.format(whitelist="\n         ".join(['host4567', 'foo', 'host1234', 'bar']))),
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': 'DONTCARE',
                'target_username': 'DONTCARE',
                'gateway_groups': []
            },
            'expected_verdict': 'ACCEPT'
        },
        id='Target IP resolved to one host in multiline whitelist is accepted',
    )

    yield pytest.param(
        {
            'target_ip_resolved': ['badhost1', 'host1234', 'badhost2'],
            'config': dedent("""[hosts_for_groups]\n__all__ = {whitelist}\n
                """.format(whitelist='\n         '.join(['host4567', 'foo', 'host1234', 'bar']))),
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': 'DONTCARE',
                'target_username': 'DONTCARE',
                'gateway_groups': []
            },
            'expected_verdict': 'ACCEPT'
        },
        id='Target IP resolved to multiple hosts in multiline whitelist is accepted',
    )

    yield pytest.param(
        {
            'target_ip_resolved': [],
            'config': dedent("""[hosts_for_groups]\n__all__ = {whitelist}\n
                """.format(whitelist="\n         ".join(['host4567', 'foo', 'host1234', '1.2.3.4']))),
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': '1.2.3.4',
                'target_username': 'DONTCARE',
                'gateway_groups': []
            },
            'expected_verdict': 'ACCEPT'
        },
        id='Matching falls back to IP match if resolving failed'
    )

    yield pytest.param(
        {
            'target_ip_resolved': ['host1234'],
            'config': '[hosts_for_groups]\n__all__ = h?st*',
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': 'DONTCARE',
                'target_username': 'DONTCARE',
                'gateway_groups': []
            },
            'expected_verdict': 'ACCEPT'
        },
        id='Wildcards can be used in host lists for single resolved hostname'
    )

    yield pytest.param(
        {
            'target_ip_resolved': ['host1234', 'foobar'],
            'config': '[hosts_for_groups]\n__all__ = *bar',
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': 'DONTCARE',
                'target_username': 'DONTCARE',
                'gateway_groups': []
            },
            'expected_verdict': 'ACCEPT'
        },
        id='Wildcards can be used in host lists for multiple resolved hostname'
    )

    yield pytest.param(
        {
            'target_ip_resolved': ['host1234'],
            'config': '[hosts_for_groups]\ntest_group = host1234, other_host, foo, bar',
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': 'DONTCARE',
                'target_username': 'DONTCARE',
                'gateway_groups': ['fake_group', 'foo', 'bar', 'test_group']
            },
            'expected_verdict': 'ACCEPT'
        },
        id='Session accepted if match found for gateway group'
    )

    yield pytest.param(
        {
            'target_ip_resolved': ['host1234'],
            'config': '[groups_for_hosts]\nhost1234 = test_group',
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': 'DONTCARE',
                'target_username': 'DONTCARE',
                'gateway_groups': ['fake_group', 'test_group']
            },
            'expected_verdict': 'ACCEPT'
        },
        id='Groups for host specification works for single group'
    )

    yield pytest.param(
        {
            'target_ip_resolved': ['host1234'],
            'config': '[groups_for_hosts]\nhost* = test_group',
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': 'DONTCARE',
                'target_username': 'DONTCARE',
                'gateway_groups': ['fake_group', 'test_group']
            },
            'expected_verdict': 'ACCEPT'
        },
        id='Groups for hosts specification supports wildcards for hosts'
    )

    yield pytest.param(
        {
            'target_ip_resolved': ['host1234'],
            'config': '[groups_for_hosts]\nhost1234 = test_group',
            'params': {
                'cookie': {},
                'session_cookie': {},
                'target_server': 'DONTCARE',
                'target_username': 'DONTCARE',
                'gateway_groups': ['unauthorized_group1', 'unauthorized_group2']
            },
            'expected_verdict': 'DENY'
        },
        id='Group not on whitelist for target host is denied'
    )

    delimiter_test_config = dedent("""
        [hosts_for_groups]
        __all__ = host0, host1 host2
                  host3
    """)

    for i in range(4):
        yield pytest.param(
            {
                'target_ip_resolved': ['host' + str(i)],
                'config': delimiter_test_config,
                'params': {
                    'cookie': {},
                    'session_cookie': {},
                    'target_server': 'DONTCARE',
                    'target_username': 'DONTCARE',
                    'gateway_groups': []
                },
                'expected_verdict': 'ACCEPT'
            },
            id='Comma, space and newline delimiters all work in whitelist'
        )


@pytest.mark.parametrize('tc', provide_authorization_test_cases())
def test_authorize_hook(tc):
    def check_tc(target_ip_resolved, config, params, expected_verdict):
        with patch('safeguard.sessions.plugin.host_resolver.HostResolver.resolve_hosts_by_ip') as mock_resolver:
            mock_resolver.return_value = target_ip_resolved
            assert Plugin(configuration=config).authorize(**deepcopy(params))['verdict'] == expected_verdict

    check_tc(**tc)
