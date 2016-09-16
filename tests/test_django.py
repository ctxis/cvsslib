import pytest
from django_app.app.models import v2Model, v3Model, namedModel  # Ensure you are running py.test in the tests/ directory.

from cvsslib import cvss2, cvss3, parse_vector
from cvsslib.base_enum import BaseEnum, NotDefined
from cvsslib.contrib.django_model import KeyedEnumField
from cvsslib.example_vectors import v3_vectors, v2_vectors


class TempEnum(BaseEnum):
    SOME_VALUE = 1
    NOT_DEFINED = NotDefined(1)


def test_named_metaclass():
    base = namedModel.__bases__[0]
    assert base.__name__ == "namedMeta.django_utils"
    assert base.__module__ == "django_app.app.models"


def test_field():
    field = KeyedEnumField(TempEnum, default=TempEnum.NOT_DEFINED.name)
    assert field.get_default() == TempEnum.NOT_DEFINED.name
    assert field.get_prep_value(TempEnum.SOME_VALUE) == TempEnum.SOME_VALUE.name
    assert field.to_python(TempEnum.SOME_VALUE.name) == TempEnum.SOME_VALUE
    assert field.to_python(TempEnum.NOT_DEFINED.name) == TempEnum.NOT_DEFINED


@pytest.mark.django_db
def test_models():
    for vectors, module, model in [
        (v3_vectors, cvss3, v3Model), (v2_vectors, cvss2, v2Model)
    ]:
        for vector, expected in vectors:
            inst = model()
            inst.from_vector(
                parse_vector(vector, module)
            )
            inst.save()

            assert inst.calculate() == expected
            assert inst.to_vector() == vector

            assert inst.debug()