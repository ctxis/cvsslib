from django.db.models.base import ModelBase

from enumfields import EnumField

from cvsslib.mixin import cvss_mixin_data, utils_mixin
from cvsslib.base_enum import NotDefined


class KeyedEnumField(EnumField):
    def get_prep_value(self, value):
        return value.name

    def to_python(self, value):
        if isinstance(value, str):
            return getattr(self.enum, value)
        return super().to_python(value)


def django_mixin(module, base=ModelBase):
    # This is a function that takes a module (filled with enums and a function called 'calculate')
    # and wires it up into a Django model that we can use.

    def field_callback(name, enum_cls):
        choices = enum_cls.choices()
        nullable = any((isinstance(o, NotDefined) and o.value.value is None) or
                       o.value is None for o in enum_cls)

        default = enum_cls.get_default()

        return KeyedEnumField(enum_cls,
                              choices=choices,
                              default=default,
                              null=nullable)

    mixin_data, enum_map = cvss_mixin_data(module, field_callback)
    Utils = utils_mixin(module, enum_map)

    class CVSSMetaclass(base):
        def __new__(cls, name, bases, attrs):
            bases = (Utils,) + bases
            return super().__new__(cls, name, bases, attrs)

        @classmethod
        def __prepare__(mcs, *args, **kwargs):
            returner = super().__prepare__(*args, **kwargs)
            returner.update(mixin_data)

            return returner

    return CVSSMetaclass
