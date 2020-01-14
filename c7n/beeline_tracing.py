import os
import beeline
import functools
import contextlib
import atexit
from beeline.trace import unmarshal_trace_context

from c7n.output import tracer_outputs

HAVE_HONEYCOMB = 'HONEYCOMB_WRITE_KEY' in os.environ and 'HONEYCOMB_DATA_SET' in os.environ


@tracer_outputs.register('beeline', condition=HAVE_HONEYCOMB)
class BeelineTracer(object):
    service_name = 'cloud-custodian'

    """Tracing provides for detailed analytics of a policy execution.

    Uses native cloud provider integration (xray, stack driver trace).
    """
    def __init__(self, ctx, config=None):
        self.ctx = ctx
        self.config = config or {}
        self.metadata = {}

    @contextlib.contextmanager
    def subsegment(self, name):
        with beeline.tracer(name=name):
            yield self

    def __enter__(self):
        self.span = beeline.start_span(context={'service_name': self.service_name})

        p = self.ctx.policy
        beeline.add_context({
            "policy": p.name,
            "resource": p.resource_type
        })

        if self.ctx.options.account_id:
            beeline.add_context_field("account", self.ctx.options.account_id)

    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        metadata = self.ctx.get_metadata(('api-stats',))
        metadata.update(self.metadata)
        beeline.add_context_field('custodian.metadata', metadata)
        beeline.finish_trace(self.span)


class traceable(object):

    def __init__(self, name):
        self.name = name

    def __call__(self, func):
        functools.wraps(func)

        def _traced(*args, **kwargs):
            configure()

            trace_id, parent_id, trace_context = None, None, None
            if 'HONEYCOMB_TRACE_ID' in os.environ:
                serialized_trace = os.environ.get('HONEYCOMB_TRACE_ID')
                trace_id, parent_id, context = unmarshal_trace_context(serialized_trace)

            with beeline.tracer(name=self.name, trace_id=trace_id, parent_id=parent_id):
                if isinstance(trace_context, dict):
                    for k, v in trace_context.items():
                        beeline.add_trace_field(k, v)
                return func(*args, **kwargs)

        return _traced


def configure():
    debug_mode = 'HONEYCOMB_DEBUG' in os.environ
    beeline.init(
        writekey=os.environ.get('HONEYCOMB_WRITE_KEY'),
        dataset=os.environ.get('HONEYCOMB_DATA_SET'),
        service_name='cloud-custodian',
        debug=debug_mode,
    )
    atexit.register(beeline.close)
