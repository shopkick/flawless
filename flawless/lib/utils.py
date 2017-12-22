import json

from future.utils import iteritems


def dump_json(obj):
    return json.dumps(
        obj,
        indent=2,
        separators=(',', ': '),
        default=lambda o: dict((k, v) for k, v in iteritems(o.__dict__) if v is not None),
    )


def im_func(obj):
    if hasattr(obj, 'im_func'):
        return getattr(obj, 'im_func')
    elif hasattr(obj, '__func__'):
        return getattr(obj, '__func__')


def im_self(obj):
    if hasattr(obj, 'im_self'):
        return getattr(obj, 'im_self')
    elif hasattr(obj, '__self__'):
        return getattr(obj, '__self__')
