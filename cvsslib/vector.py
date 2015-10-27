import inspect

from cvsslib import cvss3
from cvsslib.utils import get_enums, function_caller

v3_vector_map = {}
v3_mandatory = set()

for name, enum in get_enums(cvss3):
    docstring = inspect.getdoc(enum)
    lines = docstring.strip().split("\n")
    options = {
        line.split(":")[0].lower().strip(): line.split(":")[1].strip()
        for line in lines
        }

    vector_name = options["vector"]
    v3_vector_map[vector_name] = enum
    if options.get("mandatory", "") == "yes":
        v3_mandatory.add(vector_name)


def parse_vector(vector):
    if vector.startswith("CVSS:3.0"):
        return parse_cvss3_vector(vector)
    return parse_cvss2_vector(vector)


def parse_cvss3_vector(vec):
    split = vec.split("/")

    vector_values = {}
    given_keys = set()

    for part in split:
        if not part:
            continue

        key, value = part.split(":")
        if key == "CVSS":
            continue

        if key not in v3_vector_map:
            raise RuntimeError("Unknown part {0} in vector".format(part))

        enum = v3_vector_map[key]
        value_from_key = enum.get_value_from_vector(value)
        vector_values[enum] = value_from_key
        given_keys.add(key)
        print("{key}: {enum}: {value}".format(key=key, enum=enum, value=value))

    required_diff = v3_mandatory.difference(given_keys)

    if required_diff:
        raise RuntimeError("Missing mandatory keys {0}".format(required_diff))

    def _getter(enum_type):
        return vector_values[enum_type]

    return cvss3.calculate(function_caller(_getter))
