from functools import partial
from .utils import get_enums, run_calc
from .vector import to_vector, parse_vector
import operator


class BaseCVSSUtilsMixin(object):
    ENUM_MODULE = None

    @classmethod
    def enum_module(cls):
        return cls.ENUM_MODULE

    def debug(self):
        result = []

        ordered_enums = sorted(get_enums(self, only_classes=False), key=operator.itemgetter(0))
        for name, value in ordered_enums:
            result.append("{name} = {value}".format(name=name, value=value))

        return result


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


def utils_mixin(module, enum_map):
    calculate_func = getattr(module, "calculate", None)

    if not calculate_func:
        raise RuntimeError("Cannot find 'calculate' method in {module}".format(module=module))

    class CVSSUtilsMixin(BaseCVSSUtilsMixin):
        ENUM_MODULE = module

        def _getter(self, enum_type):
            member_name = enum_map[enum_type]
            return getattr(self, member_name)

        # Make the 'calculate' method
        def calculate(self):
            return run_calc(calculate_func, getter=self._getter)

        def to_vector(self):
            return to_vector(module, self._getter)

        def from_vector(self, vector_result, **kwargs):
            if isinstance(vector_result, str):
                vector_result = parse_vector(vector_result, module, **kwargs)

            for cls, value in vector_result.items():
                attr_name = enum_map[cls]
                setattr(self, attr_name, value)

    return CVSSUtilsMixin


def class_mixin(module, base=object):
    mixin_data, enum_map = cvss_mixin_data(module)
    Utils = utils_mixin(module, enum_map)

    class CVSSMixin(Utils, base):
        def __init__(self, *args, **kwargs):
            # enum_map maps an enum class to it's attribute name.
            for thing, value in mixin_data.items():
                setattr(self, thing, value)

            super().__init__(*args, **kwargs)

        @property
        def enums(self):
            return get_enums(self, only_classes=False)

        @property
        def enums_map(self):
            return enum_map

    return CVSSMixin
