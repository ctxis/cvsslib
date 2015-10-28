from cvsslib import CVSS2State, CVSS3State
from cvsslib import cvss3, cvss2
from cvsslib.utils import get_enums


def test_cvss_class_mixin():
    v2, v3 = CVSS2State(), CVSS3State()

    # Test that an instance of every enum class is present within each of the state classes

    for cls, module in [(v2, cvss2), (v3, cvss3)]:
        enum_classes_in_module = set([x[1] for x in get_enums(module)])
        enum_classes_in_class = set([e[1].__class__ for e in get_enums(cls, only_classes=False)])

        assert enum_classes_in_class == enum_classes_in_module
