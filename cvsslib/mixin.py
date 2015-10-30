from functools import partial

from .utils import get_enums, run_calc
from .vector import to_vector


def make_attribute_name(str):
    """
    Turns strings like AttackVector and ExploitCodeMaturity into
    attack_vector and exploit_code_maturity
    """
    returner = ""

    for idx, char in enumerate(str):
        if char.isupper() and idx != 0:
            returner += "_"
        returner += char.lower()

    return returner


def cvss_mixin_data(module, field_callback=None):
    returner = {}
    enum_dict = {}

    for name, obj in get_enums(module):
        attr_name = make_attribute_name(name)
        default = obj.get_default()

        if field_callback is None:
            returner[attr_name] = default
        else:
            returner[attr_name] = field_callback(attr_name, obj)

        enum_dict[obj] = attr_name

    return returner, enum_dict


def class_mixin(module, base=object):
    calculate_func = getattr(module, "calculate", None)

    if not calculate_func:
        raise RuntimeError("Cannot find 'calculate' method in {module}".format(module=module))

    class CVSSMixin(base):
        def __init__(self, *args, **kwargs):
            mixin_data, enum_map = cvss_mixin_data(module)

            for thing, value in mixin_data.items():
                setattr(self, thing, value)

            self._enums = mixin_data
            self._enum_map = enum_map

            super().__init__(*args, **kwargs)

        def _getter(self, enum_type):
            member_name = self._enum_map[enum_type]
            return getattr(self, member_name).value

        # Make the 'calculate' method
        def calculate(self):
            return run_calc(calculate_func, getter=self._getter)

        def to_vector(self):
            return to_vector(module, self._getter)

        def from_vector(self, vector_result):
            for cls, value in vector_result.items():
                attr_name = self._enum_map[cls]
                setattr(self, attr_name, value)

    return CVSSMixin
