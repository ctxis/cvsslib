from enumfields.fields import EnumFieldMixin  # Requires the 'django-enumfields' package

from cvsslib.mixin import cvss_mixin_data
from cvsslib import cvss2, cvss3
from cvsslib.base_enum import NotDefined
from django.db import models
from django.db.models.base import ModelBase


class DecimalEnumField(EnumFieldMixin, models.DecimalField):
    pass


def django_mixin(module, base=ModelBase):
    # This is a function that takes a module (filled with enums and a function called 'calculate')
    # and wires it up into a Django model that we can use.

    def field_callback(name, enum_cls):
        choices = enum_cls.choices()
        nullable = any((isinstance(o, NotDefined) and o.value.value is None) or
                       o.value is None for o in enum_cls)

        value = enum_cls.get_default().value
        if isinstance(value, NotDefined):
            value = value.value

        return DecimalEnumField(enum_cls,
                                max_digits=7,
                                decimal_places=4,
                                choices=choices,
                                default=value,
                                null=nullable)

    class CVSSMetaclass(base):
        @classmethod
        def __prepare__(mcs, *args, **kwargs):
            returner = super().__prepare__(*args, **kwargs)

            mixin_data, _ = cvss_mixin_data(module, field_callback)
            returner.update(mixin_data)

            return returner

    return CVSSMetaclass


class CVSS2Model(models.Model, metaclass=django_mixin(cvss2)):
    class Meta:
        abstract = True


class CVSS3Model(models.Model, metaclass=django_mixin(cvss3)):
    class Meta:
        abstract = True
