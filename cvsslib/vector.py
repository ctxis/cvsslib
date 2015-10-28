import inspect

from cvsslib import cvss3, cvss2
from cvsslib.utils import get_enums, run_calc


def parse_vector(vector, module=None):
    if module is None:
        if vector.startswith("CVSS:3.0"):
            module = cvss3
        else:
            module = cvss2

    vector_map, vector_values = {}, {}
    mandatory_keys, given_keys = set(), set()

    for name, enum in get_enums(module):
        docstring = inspect.getdoc(enum)
        lines = docstring.strip().split("\n")
        options = {
            line.split(":")[0].lower().strip(): line.split(":")[1].strip()
            for line in lines
            }

        vector_name = options["vector"]
        vector_map[vector_name] = enum
        if options.get("mandatory", "") == "yes":
            mandatory_keys.add(vector_name)

    split_vector = vector.split("/")

    for part in split_vector:
        if not part:
            continue

        key, value = part.split(":")

        if key == "CVSS":
            continue  # CVSS3 is prefixed with CVSS:3.0/

        if key not in vector_map:
            raise RuntimeError("Unknown key {0} in {1} vector".format(key, module.__name__))

        enum = vector_map[key]
        value_from_key = enum.get_value_from_vector(value)
        vector_values[enum] = value_from_key
        given_keys.add(key)

        print("{0} = {1} ({2})".format(enum, value_from_key, key))

    required_diff = mandatory_keys.difference(given_keys)

    if required_diff:
        raise RuntimeError("Missing mandatory keys {0}".format(required_diff))

    def _getter(enum_type):
        if enum_type not in vector_values:
            return enum_type.get_default()
        return vector_values[enum_type]

    return run_calc(module.calculate, getter=_getter)



