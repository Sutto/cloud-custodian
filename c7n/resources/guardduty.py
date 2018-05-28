# Copyright 2016-2018 Capital One Services, LLC
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

from c7n.manager import resources
from c7n.query import QueryResourceManager, ChildResourceManager, sources, ChildDescribeSource, TypeInfo
from c7n.utils import local_session, chunks
from itertools import chain

@resources.register('guardduty-detector')
class Detector(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'guardduty'
        enum_spec = ('list_detectors', 'DetectorIds', None)
        detail_spec = ("get_detector", 'DetectorId', None, None)
        id = 'DetectorId'
        name = None
        date = None
        dimension = None
        arn = False
        config_type = "AWS::GuardDuty::Detector"
        filter_name = None

    @classmethod
    def has_arn(self):
        return False

@sources.register('get-guardduty-findings')
class GetGuardDutyFindings(ChildDescribeSource):

    def get_query(self):
        query = super(GetGuardDutyFindings, self).get_query()
        query.capture_parent_id = True
        return query

    def augment(self, resources):
        output = []
        grouped = {}
        for parent_id, resource in resources:
            if parent_id not in grouped:
                grouped[parent_id] = []
            grouped[parent_id].append(resource)
        manager = self.manager
        for (parent_id, subset) in grouped.items():
            client = local_session(manager.session_factory).client('guardduty', region_name=manager.config.region)

            for batch in chunks(subset, 50):
                response = client.get_findings(
                    DetectorId=parent_id,
                    FindingIds=batch
                )

                output.append(response['Findings'])

        return list(chain.from_iterable(output))

@resources.register('guardduty-finding')
class Finding(ChildResourceManager):

    child_source= 'get-guardduty-findings'

    class resource_type(TypeInfo):
        service = 'guardduty'
        parent_spec = ('guardduty-detector', 'DetectorId', None)
        enum_spec = ('list_findings', 'FindingIds', None)
        id = 'Id'
        name = None
        date = None
        dimension = None
        config_type = "AWS::GuardDuty::Finding"
        filter_name = None
        arn = False
