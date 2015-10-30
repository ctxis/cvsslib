from cvsslib.mixin import cvss_mixin_data
from cvsslib import cvss2, cvss3
from django.db import models
from django.db.models.base import ModelBase


def django_mixin(module, base=ModelBase):
    # This is a function that takes a module (filled with enums and a function called 'calculate')
    # and wires it up into a Django model that we can use.

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


class CVSS2Model(models.Model, metaclass=django_mixin(cvss2)):
    class Meta:
        abstract = True


class CVSS3Model(models.Model, metaclass=django_mixin(cvss3)):
    class Meta:
        abstract = True
