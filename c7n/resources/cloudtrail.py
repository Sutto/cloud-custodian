# Copyright 2017-2019 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import, division, print_function, unicode_literals

import logging

from c7n.actions import Action, BaseAction
from c7n.exceptions import PolicyValidationError
from c7n.filters import ValueFilter, Filter, FilterRegistry, OPERATORS
from c7n.manager import resources
from c7n.tags import universal_augment
from c7n.query import DescribeSource, QueryResourceManager, TypeInfo
from c7n.utils import local_session, type_schema
from .aws import shape_validate, Arn
import re

log = logging.getLogger('c7n.resources.cloudtrail')
filters = FilterRegistry('cloudtrail.filters')

@resources.register('cloudtrail')
class CloudTrail(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'cloudtrail'
        enum_spec = ('describe_trails', 'trailList', None)
        filter_name = 'trailNameList'
        filter_type = 'list'
        arn = id = 'TrailARN'
        name = 'Name'
        config_type = "AWS::CloudTrail::Trail"
        universal_taggable = object()

    def get_source(self, source_type):
        if source_type == 'describe':
            return DescribeTrail(self)
        return super(CloudTrail, self).get_source(source_type)

    filter_registry = filters


class DescribeTrail(DescribeSource):

    def augment(self, resources):
        return universal_augment(self.manager, resources)

@filters.register('is-shadow')
class IsShadow(Filter):
    """Identify shadow trails (secondary copies), shadow trails
    can't be modified directly, the origin trail needs to be modified.

    Shadow trails are created for multi-region trails as well for
    organizational trails.
    """
    schema = type_schema('is-shadow', state={'type': 'boolean'})
    permissions = ('cloudtrail:DescribeTrails',)
    embedded = False

    def process(self, resources, event=None):
        rcount = len(resources)
        trails = [t for t in resources if (self.is_shadow(t) == self.data.get('state', True))]
        if len(trails) != rcount and self.embedded:
            self.log.info("implicitly filtering shadow trails %d -> %d",
                     rcount, len(trails))
        return trails

    def is_shadow(self, t):
        if t.get('IsOrganizationTrail') and self.manager.config.account_id not in t['TrailARN']:
            return True
        if t.get('IsMultiRegionTrail') and t['HomeRegion'] != self.manager.config.region:
            return True
        return False


@filters.register('status')
class Status(ValueFilter):
    """Filter a cloudtrail by its status.

    :Example:

    .. code-block:: yaml

        policies:
          - name: cloudtrail-check-status
            resource: aws.cloudtrail
            filters:
            - type: status
              key: IsLogging
              value: False
    """

    schema = type_schema('status', rinherit=ValueFilter.schema)
    schema_alias = False
    permissions = ('cloudtrail:GetTrailStatus',)
    annotation_key = 'c7n:TrailStatus'

    def process(self, resources, event=None):
        for r in resources:
            region = self.manager.config.region
            trail_arn = Arn.parse(r['TrailARN'])

            if (r.get('IsOrganizationTrail') and
                    self.manager.config.account_id != trail_arn.account_id):
                continue
            if r.get('HomeRegion') and r['HomeRegion'] != region:
                region = trail_arn.region
            if self.annotation_key in r:
                continue
            client = local_session(self.manager.session_factory).client(
                'cloudtrail', region_name=region)
            status = client.get_trail_status(Name=r['Name'])
            status.pop('ResponseMetadata')
            r[self.annotation_key] = status

        return super(Status, self).process(resources)

    def __call__(self, r):
        return self.match(r['c7n:TrailStatus'])


@CloudTrail.action_registry.register('update-trail')
class UpdateTrail(Action):
    """Update trail attributes.

    :Example:

    .. code-block:: yaml

       policies:
         - name: cloudtrail-set-log
           resource: aws.cloudtrail
           filters:
            - or:
              - KmsKeyId: empty
              - LogFileValidationEnabled: false
           actions:
            - type: update-trail
              attributes:
                KmsKeyId: arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef
                EnableLogFileValidation: true
    """
    schema = type_schema(
        'update-trail',
        attributes={'type': 'object'},
        required=('attributes',))
    shape = 'UpdateTrailRequest'
    permissions = ('cloudtrail:UpdateTrail',)

    def validate(self):
        attrs = dict(self.data['attributes'])
        if 'Name' in attrs:
            raise PolicyValidationError(
                "Can't include Name in update-trail action")
        attrs['Name'] = 'PolicyValidation'
        return shape_validate(
            attrs,
            self.shape,
            self.manager.resource_type.service)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('cloudtrail')
        shadow_check = IsShadow({'state': False}, self.manager)
        shadow_check.embedded = True
        resources = shadow_check.process(resources)

        for r in resources:
            client.update_trail(
                Name=r['Name'],
                **self.data['attributes'])


@CloudTrail.action_registry.register('set-logging')
class SetLogging(Action):
    """Set the logging state of a trail

    :Example:

    .. code-block:: yaml

      policies:
        - name: cloudtrail-set-active
          resource: aws.cloudtrail
          filters:
           - type: status
             key: IsLogging
             value: False
          actions:
           - type: set-logging
             enabled: True
    """
    schema = type_schema(
        'set-logging', enabled={'type': 'boolean'})

    def get_permissions(self):
        enable = self.data.get('enabled', True)
        if enable is True:
            return ('cloudtrail:StartLogging',)
        else:
            return ('cloudtrail:StopLogging',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('cloudtrail')
        shadow_check = IsShadow({'state': False}, self.manager)
        shadow_check.embedded = True
        resources = shadow_check.process(resources)
        enable = self.data.get('enabled', True)

        for r in resources:
            if enable:
                client.start_logging(Name=r['Name'])
            else:
                client.stop_logging(Name=r['Name'])



@CloudTrail.action_registry.register('delete')
class DeleteTrail(BaseAction):
    """ Delete a cloud trail

    :example:

    .. code-block:: yaml

      policies:
        - name: delete-cloudtrail
          resource: aws.cloudtrail
          filters:
           - type: value
             key: Name
             value: delete-me
             op: eq
          actions:
           - type: delete
    """

    schema = type_schema('delete')
    permissions = ('cloudtrail:DeleteTrail',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('cloudtrail')
        shadow_check = IsShadow({'state': False}, self.manager)
        shadow_check.embedded = True
        resources = shadow_check.process(resources)
        for r in resources:
            try:
                client.delete_trail(Name=r['Name'])
            except client.exceptions.TrailNotFoundException:
                continue

@filters.register('monitored-metric')
class MonitoredCloudtrailMetric(ValueFilter):
    """Finds cloudtrails with logging and a metric filter. Is a subclass of ValueFilter,
    filtering the metric filter objects. Optionally, verifies an alarm exists (true by default),
    and for said alarm, there is atleast one SNS subscription (again, true by default).

    :example:

        .. code-block: yaml

            policies:
              - name: cloudtrail-trail-with-login-attempts
                resource: cloudtrail
                region: us-east-1
                filters:
                  - type: monitored-metric
                    alarm: true
                    topic-subscription: false
                    filter: '$.eventName = DeleteTrail'
    """

    schema = type_schema('monitored-metric', rinherit=ValueFilter.schema, **{
        'topic-subscription': {'type': 'boolean'},
        'alarm': {'type': 'boolean'}
    })

    permissions = ('logs:DescribeMetricFilters', 'cloudwatch:DescribeAlarms',
        'sns:ListSubscriptionsByTopic')

    def _filterTopicArnsToSubscribed(self, session, topicArns):
        sns = session.client('sns')

        def arnHasSubscriptions(arn):
            subscriptions = sns.list_subscriptions_by_topic(TopicArn=arn)['Subscriptions']
            return any(subscriptions)
        return filter(arnHasSubscriptions, topicArns)

    def _allAlarms(self):
        return self.manager.get_resource_manager('alarm').resources()

    def _metricFiltersForLogGroup(self, session, groupName):
        logs = session.client('logs')
        paginator = logs.get_paginator('describe_metric_filters')
        results = paginator.paginate(logGroupName=groupName).build_full_result()
        return results['metricFilters']

    def _alarmInMetrics(self, alarm, metrics):
        pair = (alarm['Namespace'], alarm['MetricName'])
        return pair in metrics

    def checkResourceMetricFilters(self, resource):
        logGroupArn = resource.get('CloudWatchLogsLogGroupArn')
        if not logGroupArn:
            return False

        session = local_session(self.manager.session_factory)

        groupName = re.search(':log-group:([^:]+)', logGroupArn).group(1)
        filters = self._metricFiltersForLogGroup(session, groupName)
        matchingFilters = filter(lambda mf: self.match(mf), filters)
        if not matchingFilters:
            return False
        resource['c7n:matching-metric-filters'] = matchingFilters

        # We need to filter the list of transformations to those that emit a value, and then put
        # it into a format we can easily cross compare on.
        allTransformations = map(lambda filter: filter['metricTransformations'], matchingFilters)
        transformations = sum(allTransformations, [])
        emittedMetrics = map(lambda t: (t['metricNamespace'], t['metricName']), transformations)
        if not emittedMetrics:
            return False
        resource['c7n:emitted-metric-filters'] = emittedMetrics

        consideredSet = emittedMetrics

        if self.data.get('alarm', True):
            metricAlarms = self._allAlarms()

            def alarmFilter(alarm):
                return self._alarmInMetrics(alarm, emittedMetrics)
            filteredAlarms = filter(alarmFilter, metricAlarms)
            if not filteredAlarms:
                return False
            consideredSet = filteredAlarms
            resource['c7n:metric-filter-alarms'] = filteredAlarms
            if self.data.get('topic-subscription'):
                alarmSNSTopics = sum(map(lambda alarm: alarm['AlarmActions'], filteredAlarms), [])
                if not alarmSNSTopics:
                    return False
                consideredSet = self._filterTopicArnsToSubscribed(session, alarmSNSTopics)
                resource['c7n:subscribed-metric-filter-alarm-topics'] = consideredSet

        return any(consideredSet)

    def process(self, resources, event=None):
        return [resource for resource in resources if self.checkResourceMetricFilters(resource)]

@filters.register('in-home-region')
class InHomeRegionFilter(Filter):
    """Filters for all cloudtrail trails that are currently in their home region.

    :example:

    .. code-block:: yaml

            policies:
              - name: cloudtrail-in-home-region
                resource: cloudtrail
                filters:
                  - type: in-home-region
                actions:
                  - delete-global-grants
    """
    schema = type_schema('in-home-region')

    def process(self, trails, event=None):
        session = local_session(self.manager.session_factory)
        current_region = session.region_name
        return [t for t in trails if t['HomeRegion'] == current_region]

@CloudTrail.filter_registry.register('trail-status')
class TrailStatusFilter(ValueFilter):
    schema = type_schema('trail-status', rinherit=ValueFilter.schema)
    permissions = ('cloudtrail:GetTrailStatus',)

    def process(self, resources, event=None):
        client = local_session(self.manager.session_factory).client('cloudtrail')
        matches = []
        for item in resources:
            if 'c7n:TrailStatus' not in item:
                status = self.manager.retry(client.get_trail_status, Name=item['TrailARN'])
                item['c7n:TrailStatus'] = status
            if self.match(item['c7n:TrailStatus']):
                matches.append(item)
        return matches
