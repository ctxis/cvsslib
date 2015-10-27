import functools
import inspect
from utils import get_enums, function_caller


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


def django_mixin(module, base=None):
    # This is a function that takes a module (filled with enums and a function called 'calculate')
    # and wires it up into a Django model that we can use.

    from django.db import models
    from django.db.models.base import ModelBase

    base = base or ModelBase

    class ScoringMetaclass(base):
        @classmethod
        def __prepare__(mcs, *args, **kwargs):
            returner = super().__prepare__(*args, **kwargs)

            enum_dict = {}

            for name, obj in get_enums(module):
                attr_name = make_attribute_name(name)
                choices = obj.choices()

                if hasattr(obj, "NONE"):
                    default = obj.NONE.value
                elif hasattr(obj, "NOT_DEFINED"):
                    default = obj.NOT_DEFINED.value
                else:
                    default = min(o.value for o in obj)

                nullable = any(o.value is None for o in obj)

                returner[attr_name] = models.DecimalField(max_digits=7,
                                                          decimal_places=4,
                                                          choices=choices,
                                                          default=default,
                                                          null=nullable)

                enum_dict[obj] = attr_name

            calculate_func = getattr(module, "calculate", None)

            if not calculate_func:
                raise RuntimeError("Cannot find 'calculate' method in {module}".format(module=module))

            # Make the 'calculate' method
            def model_calculate(self):
                def _getter(enum_type):
                    member_name = enum_dict[enum_type]
                    return getattr(self, member_name)

                return calculate_func(function_caller(_getter))

            returner["calculate"] = model_calculate

            return returner

    return ScoringMetaclass
