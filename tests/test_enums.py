from cvsslib.base_enum import BaseEnum, NotDefined


class TempEnum(BaseEnum):
    SOME_VALUE = 1
    NOT_DEFINED = NotDefined(1)


new_enum = TempEnum.extend("NewEnum", {
    "SOME_OTHER_VALUE": 2,
    "_vectors": {
        "SOV": "SOME_OTHER_VALUE"
    }
})


def test_not_defined_value():
    assert TempEnum.NOT_DEFINED.name == "NOT_DEFINED"


def test_extend_enum():
    assert new_enum.SOME_OTHER_VALUE.get_value_key() == "SOV"
