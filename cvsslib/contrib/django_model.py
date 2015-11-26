import operator

from django.db.models.base import ModelBase

from enumfields import EnumField

from cvsslib.mixin import cvss_mixin_data, utils_mixin
from cvsslib.base_enum import NotDefined


class KeyedEnumField(EnumField):
    """
    An enum field that stores the names of the values as strings, rather than the values.
    """
    def get_prep_value(self, value):
        if isinstance(value, str):
            return value

        return value.name

    def to_python(self, value):
        if isinstance(value, str):
            return getattr(self.enum, value)
        return super().to_python(value)

    def get_default(self):
        if self.has_default():
            if self.default is None:
                return None

            if isinstance(self.default, str):
                return self.default

        return super().get_default()


def django_mixin(module, base=ModelBase, attr_name=None):
    # This is a function that takes a module (filled with enums and a function called 'calculate')
    # and wires it up into a Django model that we can use.

    def field_callback(name, enum_cls):
        choices = enum_cls.choices()
        nullable = any((isinstance(o, NotDefined) and o.value.value is None) or
                       o.value is None for o in enum_cls)

        max_length = max(len(o.name) for o in enum_cls)

        default = enum_cls.get_default()

        return KeyedEnumField(enum_cls,
                              choices=choices,
                              default=default.name,
                              max_length=max_length,
                              null=nullable)

    mixin_data, enum_map = cvss_mixin_data(module, field_callback)
    Utils = utils_mixin(module, enum_map)

    class DjangoUtils(Utils):
        def debug(self):
            result = []
            fields = [(field.attname, getattr(self, field.attname))
                      for field in self._meta.get_fields()
                      if isinstance(field, KeyedEnumField)]

            ordered_enums = sorted(fields, key=operator.itemgetter(0))
            for name, value in ordered_enums:
                result.append("{name} = {value}".format(name=name, value=value))

            return result

    class MetaClass(base):
        def __new__(cls, name, bases, attrs):
            cls_base = DjangoUtils

            if "__module__" in attrs:
                DjangoUtils.__module__ = attrs["__module__"]

            bases = (cls_base,) + bases

            return super().__new__(cls, name, bases, attrs)

        @classmethod
        def __prepare__(mcs, *args, **kwargs):
            returner = super().__prepare__(*args, **kwargs)
            returner.update(mixin_data)

            return returner

    MetaClass.django_utils = DjangoUtils

    if attr_name:
        DjangoUtils.__name__ = attr_name + ".django_utils"

    return MetaClass
