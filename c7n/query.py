# Copyright 2016-2017 Capital One Services, LLC
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
"""
Query capability built on skew metamodel

tags_spec -> s3, elb, rds
"""
from __future__ import absolute_import, division, print_function, unicode_literals

import functools
import itertools
import jmespath
import json

import six
from botocore.client import ClientError
from botocore.paginate import set_value_from_jmespath
from concurrent.futures import as_completed

from c7n.actions import ActionRegistry
from c7n.filters import FilterRegistry, MetricsFilter
from c7n.tags import register_ec2_tags, register_universal_tags
from c7n.utils import (
    local_session, generate_arn, get_retry, chunks, camelResource)
from c7n.registry import PluginRegistry
from c7n.manager import ResourceManager


class ResourceQuery(object):

    def __init__(self, session_factory):
        self.session_factory = session_factory

    @staticmethod
    def resolve(resource_type):
        if not isinstance(resource_type, type):
            raise ValueError(resource_type)
        else:
            m = resource_type
        return m

    def _invoke_client_enum(self, client, enum_op, params, path, retry=None):
        if client.can_paginate(enum_op):
            p = client.get_paginator(enum_op)
            results = p.paginate(**params)
            if retry:
                data = pager(results, retry)
            else:
                data = results.build_full_result()
        else:
            op = getattr(client, enum_op)
            data = op(**params)

        if path:
            path = jmespath.compile(path)
            data = path.search(data)

        return data

    def filter(self, resource_type, **params):
        """Query a set of resources."""
        m = self.resolve(resource_type)
        client = local_session(self.session_factory).client(
            m.service)

        enum_op, path, extra_args = m.enum_spec
        if extra_args:
            params.update(extra_args)

        if getattr(m, 'parent_enum_spec', None):
            parent_resource_type, id_path, param_key, parent_batchable = getattr(m, 'parent_enum_spec', None)

            parent_id_path = jmespath.compile(id_path)
            parent_resources = self.filter(parent_resource_type.resource_type)
            parent_ids = parent_id_path.search(parent_resources)
            # Bail out with no parent ids...

            existing_param = param_key in params

            if not existing_param and len(parent_ids) == 0:
                return []
            # Handle the param contextual scoping...
            if existing_param:
                data = self.invoke_client_enum(client, enum_op, params, path)
            elif parent_batchable:
                params[param_key] = parent_ids
                data = self.invoke_client_enum(client, enum_op, params, path)
            else:
                # We need to invoke the op for each item here, which kind of sucks...
                results = []
                for parent_id in parent_ids:
                    merged_params = dict(params, **{param_key: parent_id})
                    subset = self.invoke_client_enum(client, enum_op, merged_params, path)
                    results.extend(subset)
                data = results
        else:
            data = self.invoke_client_enum(client, enum_op, params, path)

        if data is None:
            data = []
        return data

    def filter(self, resource_manager, **params):
        """Query a set of resources."""
        m = self.resolve(resource_manager.resource_type)
        client = local_session(self.session_factory).client(
            m.service)
        enum_op, path, extra_args = m.enum_spec
        if extra_args:
            params.update(extra_args)
        return self._invoke_client_enum(
            client, enum_op, params, path,
            getattr(resource_manager, 'retry', None)) or []

    def get(self, resource_manager, identities):
        """Get resources by identities
        """
        m = self.resolve(resource_manager.resource_type)
        params = {}
        client_filter = False

        # Try to formulate server side query
        if m.filter_name:
            if m.filter_type == 'list':
                params[m.filter_name] = identities
            elif m.filter_type == 'scalar':
                assert len(identities) == 1, "Scalar server side filter"
                params[m.filter_name] = identities[0]
        else:
            client_filter = True

        resources = self.filter(resource_manager, **params)
        if client_filter:
            # This logic was added to prevent the issue from:
            # https://github.com/capitalone/cloud-custodian/issues/1398
            if all(map(lambda r: isinstance(r, six.string_types), resources)):
                resources = [r for r in resources if r in identities]
            else:
                resources = [r for r in resources if r[m.id] in identities]

        return resources


class ChildResourceQuery(ResourceQuery):
    """A resource query for resources that must be queried with parent information.

    Several resource types can only be queried in the context of their
    parents identifiers. ie. efs mount targets (parent efs), route53 resource
    records (parent hosted zone), ecs services (ecs cluster).
    """
    def __init__(self, session_factory, manager):
        self.session_factory = session_factory
        self.manager = manager

    def filter(self, resource_manager, **params):
        """Query a set of resources."""

        m = self.resolve(resource_manager.resource_type)
        client = local_session(self.session_factory).client(m.service)

        enum_op, path, extra_args = m.enum_spec
        if extra_args:
            params.update(extra_args)

        parent_type, parent_key = m.parent_spec
        parents = self.manager.get_resource_manager(parent_type)
        parent_ids = [p[parents.resource_type.id] for p in parents.resources()]

        # Bail out with no parent ids...
        existing_param = parent_key in params
        if not existing_param and len(parent_ids) == 0:
            return []

        # Handle a query with parent id
        if existing_param:
            return self._invoke_client_enum(client, enum_op, params, path)

        # Have to query separately for each parent's children.
        results = []
        for parent_id in parent_ids:
            merged_params = dict(params, **{parent_key: parent_id})
            subset = self._invoke_client_enum(
                client, enum_op, merged_params, path)
            if subset:
                results.extend(subset)

        return results


class QueryMeta(type):

    def __new__(cls, name, parents, attrs):
        if 'resource_type' not in attrs:
            return super(QueryMeta, cls).__new__(cls, name, parents, attrs)

        if 'filter_registry' not in attrs:
            attrs['filter_registry'] = FilterRegistry(
                '%s.filters' % name.lower())
        if 'action_registry' not in attrs:
            attrs['action_registry'] = ActionRegistry(
                '%s.filters' % name.lower())

        if attrs['resource_type']:
            m = ResourceQuery.resolve(attrs['resource_type'])
            # Generic cloud watch metrics support
            if m.dimension:
                attrs['filter_registry'].register('metrics', MetricsFilter)
            # EC2 Service boilerplate ...
            if m.service == 'ec2':
                # Generic ec2 retry
                attrs['retry'] = staticmethod(get_retry((
                    'RequestLimitExceeded', 'Client.RequestLimitExceeded')))
                # Generic ec2 resource tag support
                if getattr(m, 'taggable', True):
                    register_ec2_tags(
                        attrs['filter_registry'], attrs['action_registry'])
            if getattr(m, 'universal_taggable', False):
                register_universal_tags(
                    attrs['filter_registry'], attrs['action_registry'])

        return super(QueryMeta, cls).__new__(cls, name, parents, attrs)


def _napi(op_name):
    return op_name.title().replace('_', '')


sources = PluginRegistry('sources')


@sources.register('describe')
class DescribeSource(object):

    def __init__(self, manager):
        self.manager = manager
        self.query = ResourceQuery(self.manager.session_factory)

    def get_resources(self, ids, cache=True):
        return self.query.get(self.manager, ids)

    def resources(self, query):
        return self.query.filter(self.manager, **query)

    def get_permissions(self):
        m = self.manager.get_model()
        perms = ['%s:%s' % (m.service, _napi(m.enum_spec[0]))]
        if getattr(m, 'detail_spec', None):
            perms.append("%s:%s" % (m.service, _napi(m.detail_spec[0])))
        return perms

    def augment(self, resources):
        model = self.manager.get_model()
        if getattr(model, 'detail_spec', None):
            detail_spec = getattr(model, 'detail_spec', None)
            _augment = _scalar_augment
        elif getattr(model, 'batch_detail_spec', None):
            detail_spec = getattr(model, 'batch_detail_spec', None)
            _augment = _batch_augment
        else:
            return resources
        _augment = functools.partial(
            _augment, self.manager, model, detail_spec)
        with self.manager.executor_factory(
                max_workers=self.manager.max_workers) as w:
            results = list(w.map(
                _augment, chunks(resources, self.manager.chunk_size)))
            return list(itertools.chain(*results))


@sources.register('describe-child')
class ChildDescribeSource(DescribeSource):

    def __init__(self, manager):
        self.manager = manager
        self.query = ChildResourceQuery(
            self.manager.session_factory, self.manager)


@sources.register('config')
class ConfigSource(object):

    retry = staticmethod(get_retry(('ThrottlingException',)))

    def __init__(self, manager):
        self.manager = manager

    def get_permissions(self):
        return ["config:GetResourceConfigHistory",
                "config:ListDiscoveredResources"]

    def get_resources(self, ids, cache=True):
        client = local_session(self.manager.session_factory).client('config')
        results = []
        m = self.manager.get_model()
        for i in ids:
            revisions = self.retry(
                client.get_resource_config_history,
                resourceId=i,
                resourceType=m.config_type,
                limit=1).get('configurationItems')
            if not revisions:
                continue
            results.append(self.load_resource(revisions[0]))
        return filter(None, results)

    def load_resource(self, item):
        if isinstance(item['configuration'], six.string_types):
            item_config = json.loads(item['configuration'])
        else:
            item_config = item['configuration']
        return camelResource(item_config)

    def resources(self, query=None):
        client = local_session(self.manager.session_factory).client('config')
        paginator = client.get_paginator('list_discovered_resources')
        pages = paginator.paginate(
            resourceType=self.manager.get_model().config_type)
        results = []

        with self.manager.executor_factory(max_workers=5) as w:
            ridents = pager(pages, self.retry)
            resource_ids = [
                r['resourceId'] for r in ridents.get('resourceIdentifiers', ())]
            self.manager.log.debug(
                "querying %d %s resources",
                len(resource_ids),
                self.manager.__class__.__name__.lower())

            for resource_set in chunks(resource_ids, 50):
                futures = []
                futures.append(w.submit(self.get_resources, resource_set))
                for f in as_completed(futures):
                    if f.exception():
                        self.manager.log.error(
                            "Exception getting resources from config \n %s" % (
                                f.exception()))
                    results.extend(f.result())
        return results

    def augment(self, resources):
        return resources


def pager(p, retry):
    results = {}
    iterator = iter(p)

    while True:
        try:
            page = retry(next, iterator)
        except StopIteration:
            return results
        if isinstance(page, tuple) and len(page) == 2:
            page = page[1]
        for rexpr in p.result_keys:
            rv = rexpr.search(page)
            if rv is None:
                continue
            ev = rexpr.search(results)
            if ev is None:
                set_value_from_jmespath(results, rexpr.expression, rv)
                continue
            ev.extend(rv)


@six.add_metaclass(QueryMeta)
class QueryResourceManager(ResourceManager):

    resource_type = ""

    retry = None

    # TODO Check if we can move to describe source
    max_workers = 3
    chunk_size = 20

    permissions = ()

    _generate_arn = None

    def __init__(self, data, options):
        super(QueryResourceManager, self).__init__(data, options)
        self.source = self.get_source(self.source_type)

    @property
    def source_type(self):
        return self.data.get('source', 'describe')

    def get_source(self, source_type):
        return sources.get(source_type)(self)

    @classmethod
    def get_model(cls):
        return ResourceQuery.resolve(cls.resource_type)

    @classmethod
    def match_ids(cls, ids):
        """return ids that match this resource type's id format."""
        id_prefix = getattr(cls.get_model(), 'id_prefix', None)
        if id_prefix is not None:
            return [i for i in ids if i.startswith(id_prefix)]
        return ids

    def get_permissions(self):
        perms = self.source.get_permissions()
        if getattr(self, 'permissions', None):
            perms.extend(self.permissions)
        return perms

    def resources(self, query=None):
        key = {'region': self.config.region,
               'resource': str(self.__class__.__name__),
               'q': query}

        if self._cache.load():
            resources = self._cache.get(key)
            if resources is not None:
                self.log.debug("Using cached %s: %d" % (
                    "%s.%s" % (self.__class__.__module__,
                               self.__class__.__name__),
                    len(resources)))
                return self.filter_resources(resources)

        if query is None:
            query = {}

        resources = self.augment(self.source.resources(query))
        self._cache.save(key, resources)
        return self.filter_resources(resources)

    def get_resources(self, ids, cache=True):
        key = {'region': self.config.region,
               'resource': str(self.__class__.__name__),
               'q': None}
        if cache and self._cache.load():
            resources = self._cache.get(key)
            if resources is not None:
                self.log.debug("Using cached results for get_resources")
                m = self.get_model()
                id_set = set(ids)
                return [r for r in resources if r[m.id] in id_set]
        try:
            resources = self.augment(self.source.get_resources(ids))
            return resources
        except ClientError as e:
            self.log.warning("event ids not resolved: %s error:%s" % (ids, e))
            return []

    def augment(self, resources):
        """subclasses may want to augment resources with additional information.

        ie. we want tags by default (rds, elb), and policy, location, acl for
        s3 buckets.
        """
        return self.source.augment(resources)

    @property
    def account_id(self):
        """ Return the current account ID.

        This should now be passed in using the --account-id flag, but for a
        period of time we will support the old behavior of inferring this from
        IAM.
        """
        return self.config.account_id

    def get_arns(self, resources):
        arns = []
        for r in resources:
            _id = r[self.get_model().id]
            if 'arn' in _id[:3]:
                arns.append(_id)
            else:
                arns.append(self.generate_arn(_id))
        return arns

    @property
    def generate_arn(self):
        """ Generates generic arn if ID is not already arn format.
        """
        if self._generate_arn is None:
            self._generate_arn = functools.partial(
                generate_arn,
                self.get_model().service,
                region=self.config.region,
                account_id=self.account_id,
                resource_type=self.get_model().type,
                separator='/')
        return self._generate_arn


class ChildResourceManager(QueryResourceManager):

    @property
    def source_type(self):
        source = self.data.get('source', 'describe-child')
        if source == 'describe':
            source = 'describe-child'
        return source


def _batch_augment(manager, model, detail_spec, resource_set):
    detail_op, param_name, param_key, detail_path = detail_spec
    client = local_session(manager.session_factory).client(model.service)
    op = getattr(client, detail_op)
    if manager.retry:
        args = (op,)
        op = manager.retry
    else:
        args = ()
    kw = {param_name: [param_key and r[param_key] or r for r in resource_set]}
    response = op(*args, **kw)
    return response[detail_path]


def _scalar_augment(manager, model, detail_spec, resource_set):
    detail_op, param_name, param_key, detail_path = detail_spec
    client = local_session(manager.session_factory).client(model.service)
    op = getattr(client, detail_op)
    if manager.retry:
        args = (op,)
        op = manager.retry
    else:
        args = ()
    results = []
    for r in resource_set:
        kw = {param_name: param_key and r[param_key] or r}
        response = op(*args, **kw)
        if detail_path:
            response = response[detail_path]
        else:
            response.pop('ResponseMetadata')
        if param_key is None:
            response[model.id] = r
            r = response
        else:
            r.update(response)
        results.append(r)
    return results
