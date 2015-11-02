from django.db import models

from cvsslib.contrib.django_model import django_mixin
from cvsslib import cvss2, cvss3

v2Meta = django_mixin(cvss2)
v3Meta = django_mixin(cvss3)


class v2Model(models.Model, metaclass=v2Meta):
    pass


class v3Model(models.Model, metaclass=v3Meta):
    pass
