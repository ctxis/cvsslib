from cvsslib.base_enum import BaseEnum, NotDefined


class TempEnum(BaseEnum):
    SOME_VALUE = 1
    NOT_DEFINED = NotDefined(1)


def test_not_defined_value():
    assert TempEnum.NOT_DEFINED.name == "NOT_DEFINED"
