#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: bigip_firewall_dos_vector
short_description: Manage attack vector configuration in an AFM DoS profile
description:
  - Manage attack vector configuration in an AFM DoS profile. In addition to the normal
    AFM DoS profile vectors, this module can manage the device-configuration vectors.
    See the module documentation for details about this method.
version_added: 2.8
options:
  name:
    description:
      - Specifies the name of the vector to modify.
      - Vectors that ship with the device are "hard-coded" so-to-speak in that the list
        of vectors is known to the system and users cannot add new vectors. Users only
        manipulate the existing vectors; all of which are disabled by default.
      - When C(ext-hdr-too-large), configures the "IPv6 extension header too large"
        Network Security vector.
      - When C(hop-cnt-low), configures the "IPv6 hop count <= <tunable>" Network
        Security vector.
      - When C(host-unreachable), configures the "Host Unreachable" Network Security
        vector.
      - When C(icmp-frag), configures the "ICMP Fragment" Network Security vector.
      - When C(icmpv4-flood), configures the "ICMPv4 flood" Network Security vector.
      - When C(icmpv6-flood), configures the "ICMPv6 flood" Network Security vector.
      - When C(ip-frag-flood), configures the "IP Fragment Flood" Network Security vector.
      - When C(ip-low-ttl), configures the "TTL <= <tunable>" Network Security vector.
      - When C(ip-opt-frames), configures the "IP Option Frames" Network Security vector.
      - When C(ipv6-ext-hdr-frames), configures the "IPv6 Extended Header Frames"
        Network Security vector.
      - When C(ipv6-frag-flood), configures the "IPv6 Fragment Flood" Network Security
        vector.
      - When C(opt-present-with-illegal-len), configures the "Option Present With Illegal
        Length" Network Security vector.
      - When C(sweep), configures the "Sweep" Network Security vector.
      - When C(tcp-bad-urg), configures the "TCP Flags-Bad URG" Network Security vector.
      - When C(tcp-half-open), configures the "TCP Half Open" Network Security vector.
      - When C(tcp-opt-overruns-tcp-hdr), configures the "TCP Option Overruns TCP Header"
        Network Security vector.
      - When C(tcp-psh-flood), configures the "TCP PUSH Flood" Network Security vector.
      - When C(tcp-rst-flood), configures the "TCP RST Flood" Network Security vector.
      - When C(tcp-syn-flood), configures the "TCP SYN Flood" Network Security vector.
      - When C(tcp-syn-oversize), configures the "TCP SYN Oversize" Network Security
        vector.
      - When C(tcp-synack-flood), configures the "TCP SYN ACK Flood" Network Security
        vector.
      - When C(tcp-window-size), configures the "TCP Window Size" Network Security
        vector.
      - When C(tidcmp), configures the "TIDCMP" Network Security vector.
      - When C(too-many-ext-hdrs), configures the "Too Many Extension Headers" Network
        Security vector.
      - When C(udp-flood), configures the "UDP Flood" Network Security vector.
      - When C(unk-tcp-opt-type), configures the "Unknown TCP Option Type" Network
        Security vector.
      - When C(a), configures the "DNS A Query" DNS Protocol Security vector.
      - When C(aaaa), configures the "DNS AAAA Query" DNS Protocol Security vector.
      - When C(any), configures the "DNS ANY Query" DNS Protocol Security vector.
      - When C(axfr), configures the "DNS AXFR Query" DNS Protocol Security vector.
      - When C(cname), configures the "DNS CNAME Query" DNS Protocol Security vector.
      - When C(dns-malformed), configures the "dns-malformed" DNS Protocol Security vector.
      - When C(ixfr), configures the "DNS IXFR Query" DNS Protocol Security vector.
      - When C(mx), configures the "DNS MX Query" DNS Protocol Security vector.
      - When C(ns), configures the "DNS NS Query" DNS Protocol Security vector.
      - When C(other), configures the "DNS OTHER Query" DNS Protocol Security vector.
      - When C(ptr), configures the "DNS PTR Query" DNS Protocol Security vector.
      - When C(qdcount), configures the "DNS QDCOUNT Query" DNS Protocol Security vector.
      - When C(soa), configures the "DNS SOA Query" DNS Protocol Security vector.
      - When C(srv), configures the "DNS SRV Query" DNS Protocol Security vector.
      - When C(txt), configures the "DNS TXT Query" DNS Protocol Security vector.
      - When C(ack), configures the "SIP ACK Method" SIP Protocol Security vector.
      - When C(bye), configures the "SIP BYE Method" SIP Protocol Security vector.
      - When C(cancel), configures the "SIP CANCEL Method" SIP Protocol Security vector.
      - When C(invite), configures the "SIP INVITE Method" SIP Protocol Security vector.
      - When C(message), configures the "SIP MESSAGE Method" SIP Protocol Security vector.
      - When C(notify), configures the "SIP NOTIFY Method" SIP Protocol Security vector.
      - When C(options), configures the "SIP OPTIONS Method" SIP Protocol Security vector.
      - When C(other), configures the "SIP OTHER Method" SIP Protocol Security vector.
      - When C(prack), configures the "SIP PRACK Method" SIP Protocol Security vector.
      - When C(publish), configures the "SIP PUBLISH Method" SIP Protocol Security vector.
      - When C(register), configures the "SIP REGISTER Method" SIP Protocol Security vector.
      - When C(sip-malformed), configures the "sip-malformed" SIP Protocol Security vector.
      - When C(subscribe), configures the "SIP SUBSCRIBE Method" SIP Protocol Security vector.
      - When C(uri-limit), configures the "uri-limit" SIP Protocol Security vector.
    choices:
      - ext-hdr-too-large
      - hop-cnt-low
      - host-unreachable
      - icmp-frag
      - icmpv4-flood
      - icmpv6-flood
      - ip-frag-flood
      - ip-low-ttl
      - ip-opt-frames
      - ipv6-frag-flood
      - opt-present-with-illegal-len
      - sweep
      - tcp-bad-urg
      - tcp-half-open
      - tcp-opt-overruns-tcp-hdr
      - tcp-psh-flood
      - tcp-rst-flood
      - tcp-syn-flood
      - tcp-syn-oversize
      - tcp-synack-flood
      - tcp-window-size
      - tidcmp
      - too-many-ext-hdrs
      - udp-flood
      - unk-tcp-opt-type
      - a
      - aaaa
      - any
      - axfr
      - cname
      - dns-malformed
      - ixfr
      - mx
      - ns
      - other
      - ptr
      - qdcount
      - soa
      - srv
      - txt
      - ack
      - bye
      - cancel
      - invite
      - message
      - notify
      - options
      - other
      - prack
      - publish
      - register
      - sip-malformed
      - subscribe
      - uri-limit
  profile:
    description:
      - Specifies the name of the profile to manage vectors in.
      - The reserved name C(device-config) represents the vec
    required: True
extends_documentation_fragment: f5
requirements:
  - BIG-IP >= v13.0.0
author:
  - Tim Rupp (@caphrim007)
'''

EXAMPLES = r'''
- name: Create a ...
  bigip_firewall_dos_vector:
    name: foo
    password: secret
    server: lb.mydomain.com
    state: present
    user: admin
  delegate_to: localhost
'''

RETURN = r'''
param1:
  description: The new param1 value of the resource.
  returned: changed
  type: bool
  sample: true
param2:
  description: The new param2 value of the resource.
  returned: changed
  type: string
  sample: Foo is bar
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.six import iteritems

try:
    from library.module_utils.network.f5.bigip import F5RestClient
    from library.module_utils.network.f5.common import F5ModuleError
    from library.module_utils.network.f5.common import AnsibleF5Parameters
    from library.module_utils.network.f5.common import cleanup_tokens
    from library.module_utils.network.f5.common import fq_name
    from library.module_utils.network.f5.common import f5_argument_spec
    from library.module_utils.network.f5.common import exit_json
    from library.module_utils.network.f5.common import fail_json
    from library.module_utils.network.f5.common import transform_name
except ImportError:
    from ansible.module_utils.network.f5.bigip import F5RestClient
    from ansible.module_utils.network.f5.common import F5ModuleError
    from ansible.module_utils.network.f5.common import AnsibleF5Parameters
    from ansible.module_utils.network.f5.common import cleanup_tokens
    from ansible.module_utils.network.f5.common import fq_name
    from ansible.module_utils.network.f5.common import f5_argument_spec
    from ansible.module_utils.network.f5.common import exit_json
    from ansible.module_utils.network.f5.common import fail_json
    from ansible.module_utils.network.f5.common import transform_name


class Parameters(AnsibleF5Parameters):
    api_map = {
        'allowAdvertisement': 'allow_advertisement',
        'autoBlacklisting': 'auto_blacklist',
        # "autoThreshold": "disabled",
        'badActor': 'bad_actor_detection',
        'blacklistDetectionSeconds': 'blacklist_detection_seconds',
        'blacklistDuration': 'blacklist_duration',
        'ceiling': 'attack_ceiling',
        # "enforce": "enabled",
        'floor': 'attack_floor',
        'blacklistCategory': 'blacklist_category',
        'perSourceIpDetectionPps': 'per_source_ip_detection_threshold',
        'perSourceIpLimitPps': 'per_source_ip_mitigation_threshold',
        'rateIncrease': 'detection_threshold_percent',
        'rateLimit': 'mitigation_threshold_eps',
        'rateThreshold': 'detection_threshold_eps',
        'simulateAutoThreshold': 'simulate_auto_threshold',
        'thresholdMode': 'threshold_mode',
    }

    api_attributes = [
        # DoS profile related
        'networkAttackVector',
        'dnsQueryVector',
        'sipAttackVector',

        # DoS Device Config related
        'dosDeviceVector'
    ]

    returnables = [
        'allow_advertisement',
        'auto_blacklist',
        'bad_actor_detection',
        'blacklist_detection_seconds',
        'blacklist_duration',
        'attack_ceiling',
        'attack_floor',
        'blacklist_category',
        'per_source_ip_detection_threshold',
        'per_source_ip_mitigation_threshold',
        'detection_threshold_percent',
        'detection_threshold_eps',
        'mitigation_threshold_eps',
        'threshold_mode',
        'simulate_auto_threshold',
    ]

    updatables = [
        'allow_advertisement',
        'auto_blacklist',
        'bad_actor_detection',
        'blacklist_detection_seconds',
        'blacklist_duration',
        'attack_ceiling',
        'attack_floor',
        'blacklist_category',
        'per_source_ip_detection_threshold',
        'per_source_ip_mitigation_threshold',
        'detection_threshold_percent',
        'detection_threshold_eps',
        'mitigation_threshold_eps',
        'threshold_mode',
        'simulate_auto_threshold',
    ]


class ApiParameters(Parameters):
    @property
    def vectors(self):
        try:
            result = []
            for x in self._values['items']['dnsQueryVector']:
                result += [(k, v) for k, v in iteritems(x)]
        except (KeyError, TypeError):
            return None
        return result


class ModuleParameters(Parameters):
    pass


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            pass
        return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    pass


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1


class BaseManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = kwargs.get('client', None)

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def exec_module(self):
        result = dict()

        changed = self.present()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def present(self):
        return self.update()

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = kwargs.get('client', None)
        self.kwargs = kwargs
        self.vectors = dict(
            network_security=[
                'ext-hdr-too-large',            # IPv6 extension header too large
                'hop-cnt-low',                  # IPv6 hop count <= <tunable>
                'host-unreachable',             # Host Unreachable
                'icmp-frag',                    # ICMP Fragment
                'icmpv4-flood',                 # ICMPv4 flood
                'icmpv6-flood',                 # ICMPv6 flood
                'ip-frag-flood',                # IP Fragment Flood
                'ip-low-ttl',                   # TTL <= <tunable>
                'ip-opt-frames',                # IP Option Frames
                'ipv6-ext-hdr-frames',          # IPv6 Extended Header Frames
                'ipv6-frag-flood',              # IPv6 Fragment Flood
                'opt-present-with-illegal-len', # Option Present With Illegal Length
                'sweep',                        # Sweep
                'tcp-bad-urg',                  # TCP Flags-Bad URG
                'tcp-half-open',                # TCP Half Open
                'tcp-opt-overruns-tcp-hdr',     # TCP Option Overruns TCP Header
                'tcp-psh-flood',                # TCP PUSH Flood
                'tcp-rst-flood',                # TCP RST Flood
                'tcp-syn-flood',                # TCP SYN Flood
                'tcp-syn-oversize',             # TCP SYN Oversize
                'tcp-synack-flood',             # TCP SYN ACK Flood
                'tcp-window-size',              # TCP Window Size
                'tidcmp',                       # TIDCMP
                'too-many-ext-hdrs',            # Too Many Extension Headers
                'udp-flood',                    # UDP Flood
                'unk-tcp-opt-type',             # Unknown TCP Option Type
            ],
            protocol_dns=[
                'a',                # DNS A Query
                'aaaa',             # DNS AAAA Query
                'any',              # DNS ANY Query
                'axfr',             # DNS AXFR Query
                'cname',            # DNS CNAME Query
                'dns-malformed',    # dns-malformed
                'ixfr',             # DNS IXFR Query
                'mx',               # DNS MX Query
                'ns',               # DNS NS Query
                'other',            # DNS OTHER Query
                'ptr',              # DNS PTR Query
                'qdcount',          # DNS QDCOUNT LIMIT
                'soa',              # DNS SOA Query
                'srv',              # DNS SRV Query
                'txt',              # DNS TXT Query
            ],
            protocol_sip=[
                'ack',              # SIP ACK Method
                'bye',              # SIP BYE Method
                'cancel',           # SIP CANCEL Method
                'invite',           # SIP INVITE Method
                'message',          # SIP MESSAGE Method
                'notify',           # SIP NOTIFY Method
                'options',          # SIP OPTIONS Method
                'other',            # SIP OTHER Method
                'prack',            # SIP PRACK Method
                'publish',          # SIP PUBLISH Method
                'register',         # SIP REGISTER Method
                'sip-malformed',    # sip-malformed
                'subscribe',        # SIP SUBSCRIBE Method
                'uri-limit',        # uri-limit
            ]
        )

    def exec_module(self):
        if self.module.params['name'] == 'device-config':
            manager = self.get_manager('v1')
        elif self.module.params['name'] in self.vectors['network_security']:
            manager = self.get_manager('v2')
        elif self.module.params['name'] in self.vectors['protocol_dns']:
            manager = self.get_manager('v3')
        elif self.module.params['name'] in self.vectors['protocol_sip']:
            manager = self.get_manager('v4')
        else:
            raise F5ModuleError(
                "Unknown vector type specified."
            )
        return manager.exec_module()

    def get_manager(self, type):
        if type == 'v1':
            return DeviceConfigManager(**self.kwargs)
        elif type == 'v2':
            return NetworkSecurityManager(**self.kwargs)
        elif type == 'v3':
            return ProtocolDnsManager(**self.kwargs)
        elif type == 'v4':
            return ProtocolSipManager(**self.kwargs)


class DeviceConfigManager(BaseManager):
    """Manages AFM DoS Device Configuration settings.

    DeviceConfiguration is a special type of profile that is specific to the
    BIG-IP device's management interface; not the data plane interfaces.

    There are many similar vectors that can be managed here. This configuration
    is a super-set of the base DoS profile vector configuration and includes
    several attributes per-vector that are not found in the DoS profile configuration.
    These include,

      * allowUpstreamScrubbing
      * attackedDst
      * autoScrubbing
      * defaultInternalRateLimit
      * detectionThresholdPercent
      * detectionThresholdPps
      * perDstIpDetectionPps
      * perDstIpLimitPps
      * scrubbingDetectionSeconds
      * scrubbingDuration
    """
    def __init__(self, *args, **kwargs):
        super(DeviceConfigManager, self).__init__(**kwargs)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/security/dos/device-config/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name('Common', 'dos-device-config')
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/security/dos/device-config/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name('Common', 'dos-device-config')
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        return ApiParameters(params=response)


class NetworkSecurityManager(BaseManager):
    """Manages AFM DoS Profile Network Security settings.

    Network Security settings are a sub-collection attached to each profile.

    There are many similar vectors that can be managed here. This configuration
    is a sub-set of the device-config DoS vector configuration and excludes
    several attributes per-vector that are found in the device-config configuration.
    These include,

      * rateIncrease
      * rateLimit
      * rateThreshold
    """
    def __init__(self, *args, **kwargs):
        super(NetworkSecurityManager, self).__init__(**kwargs)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/security/dos/profile/{2}/dos-network/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.profile),
            self.want.profile
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/security/dos/profile/{2}/dos-network/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.profile),
            self.want.profile
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        return ApiParameters(params=response)


class ProtocolDnsManager(BaseManager):
    """Manages AFM DoS Profile Protocol DNS settings.

    Protocol DNS settings are a sub-collection attached to each profile.

    There are many similar vectors that can be managed here. This configuration
    is a sub-set of the device-config DoS vector configuration and excludes
    several attributes per-vector that are found in the device-config configuration.
    These include,

      * rateIncrease
      * rateLimit
      * rateThreshold
    """
    def __init__(self, *args, **kwargs):
        super(ProtocolDnsManager, self).__init__(**kwargs)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/security/dos/profile/{2}/protocol-dns/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.profile),
            self.want.profile
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/security/dos/profile/{2}/protocol-dns/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.profile),
            self.want.profile
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        return ApiParameters(params=response)


class ProtocolSipManager(BaseManager):
    """Manages AFM DoS Profile Protocol SIP settings.

    Protocol SIP settings are a sub-collection attached to each profile.

    There are many similar vectors that can be managed here. This configuration
    is a sub-set of the device-config DoS vector configuration and excludes
    several attributes per-vector that are found in the device-config configuration.
    These include,

      * rateIncrease
      * rateLimit
      * rateThreshold
    """
    def __init__(self, *args, **kwargs):
        super(ProtocolSipManager, self).__init__(**kwargs)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/security/dos/profile/{2}/protocol-sip/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.profile),
            self.want.profile
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/security/dos/profile/{2}/protocol-sip/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.profile),
            self.want.profile
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        return ApiParameters(params=response)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            profile=dict(required=True),

            allow_advertisement=dict(type='bool'),
            auto_blacklist=dict(type='bool'),
            simulate_auto_threshold=dict(type='bool'),
            bad_actor_detection=dict(type='bool'),
            blacklist_detection_seconds=dict(type='int'),
            blacklist_duration=dict(type='int'),
            attack_ceiling=dict(),
            per_source_ip_detection_threshold=dict(),
            detection_threshold_percent=dict(
                aliases=['rate_increase']
            ),
            detection_threshold=dict(
                aliases=['rate_threshold']
            ),
            threshold_mode=dict(
                choices=['manual', 'stress-based-mitigation', 'fully-automatic']
            ),
            state=dict(
                choices=['mitigate', 'detect-only', 'learn-only', 'disabled']
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    client = F5RestClient(**module.params)

    try:
        mm = ModuleManager(module=module, client=client)
        results = mm.exec_module()
        cleanup_tokens(client)
        exit_json(module, results, client)
    except F5ModuleError as ex:
        cleanup_tokens(client)
        fail_json(module, ex, client)


if __name__ == '__main__':
    main()
