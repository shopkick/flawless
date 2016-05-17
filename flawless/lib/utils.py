import json


def dump_json(obj):
    return json.dumps(
        obj,
        indent=2,
        separators=(',', ': '),
        default=lambda o: dict((k, v) for k, v in o.__dict__.items() if v is not None),
    )
