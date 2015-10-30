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

    calculate_func = getattr(module, "calculate", None)

    if not calculate_func:
        raise RuntimeError("Cannot find 'calculate' method in {module}".format(module=module))

    def _getter(inst, enum_type):
        member_name = enum_dict[enum_type]
        return getattr(inst, member_name)

    def _from_vector(self):
        vectors = self.to_vector()

    # Make the 'calculate' method
    def _calculate(self):
        return run_calc(calculate_func, getter=partial(_getter, self))

    def _to_vector(self):
        return to_vector(module, partial(_getter, self))

    returner["to_vector"] = _to_vector
    returner["calculate"] = _calculate
    return returner


def class_mixin(module, base=object):
    class CVSSMixin(base):
        def __init__(self, *args, **kwargs):
            mixin_data = cvss_mixin_data(module)

            for thing, value in mixin_data.items():
                setattr(self, thing, value)

            # Horrible horrible hack
            setattr(self, "calculate", partial(mixin_data["calculate"], self))
            setattr(self, "to_vector", partial(mixin_data["to_vector"], self))
            self._enums = mixin_data

            super().__init__(*args, **kwargs)

    return CVSSMixin


def django_mixin(module, base=None):
    # This is a function that takes a module (filled with enums and a function called 'calculate')
    # and wires it up into a Django model that we can use.

    from django.db import models
    from django.db.models.base import ModelBase

    base = base or ModelBase

    def field_callback(name, enum_cls):
        choices = enum_cls.choices()
        nullable = any(o.value is None for o in enum_cls)

        return models.DecimalField(max_digits=7,
                                   decimal_places=4,
                                   choices=choices,
                                   default=enum_cls.get_default(),
                                   null=nullable)

    class CVSSMetaclass(base):
        @classmethod
        def __prepare__(mcs, *args, **kwargs):
            returner = super().__prepare__(*args, **kwargs)

            mixin_data = cvss_mixin_data(module, field_callback)
            returner.update(mixin_data)

            return returner

    return CVSSMetaclass
