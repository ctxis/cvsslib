from cvsslib.vector import calculate_vector, parse_vector
from cvsslib import CVSS2State, CVSS3State
from cvsslib import cvss3, cvss2
from cvsslib.utils import get_enums

v3_test_vectors = [
    ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/MAV:A/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", (4.6, 4.6, 0.0)),
    ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/MAV:A/MAC:L/MPR:N/MUI:N/MS:U/MC:L/MI:N/MA:N", (4.6, 4.6, 4.3)),
    ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/E:H/RL:W/RC:U/CR:H/IR:H/AR:M/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:H/MA:L", (5.8, 5.2, 7.4)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", (0.0, 0.0, 0.0)),
    ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (5.8, 5.8, 7.1)),
    ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:H", (8.2, 8.2, 8.2)),
    ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L/E:U/RL:U/RC:R/CR:M/MPR:L/MUI:R/MI:N/MA:H", (7.7, 6.8, 6.3)),
    ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N/E:P/RL:U/RC:U/CR:H/IR:L/AR:H/MAV:L/MUI:R/MS:C/MC:N/MI:L/MA:N", (5.3, 4.6, 1.3)),

    # Taken from the CVSS examples page: https://www.first.org/cvss/examples
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", (6.1, 6.1, 6.1)),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", (6.4, 6.4, 6.4)),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", (3.1, 3.1, 3.1)),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", (9.9, 9.9, 9.9)),
    ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", (4.2, 4.2, 4.2)),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", (8.8, 8.8, 8.8)),
    ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", (7.8, 7.8, 7.8)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", (7.5, 7.5, 7.5)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", (9.8, 9.8, 9.8)),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", (6.8, 6.8, 6.8)),
    ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", (6.8, 6.8, 6.8)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", (5.8, 5.8, 5.8)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", (5.8, 5.8, 5.8)),
    ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H", (9.3, 9.3, 9.3)),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", (5.4, 5.4, 5.4)),
    ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", (7.8, 7.8, 7.8)),
    ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", (8.8, 8.8, 8.8)),
    ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", (4.6, 4.6, 4.6)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", (8.8, 8.8, 8.8)),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", (7.4, 7.4, 7.4)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", (9.6, 9.6, 9.6))
]


v2_test_vectors = [
    ("AV:L/AC:M/Au:S/C:N/I:P/A:C/E:U/RL:OF/RC:UR/CDP:N/TD:L/CR:H/IR:H/AR:H", (5, 3.5, 1.2)),
    ("AV:N/AC:M/Au:M/C:C/I:N/A:P/RL:W/RC:UC/CDP:LM/TD:M/CR:L/IR:L/AR:L", (6.4, 5.5, 4)),
    ("AV:L/AC:L/Au:S/C:P/I:P/A:P/E:U/RC:C/CDP:LM/TD:L/IR:H/AR:M", (4.3, 3.7, 1.5)),
    ("AV:A/AC:M/Au:S/C:C/I:P/A:C", (7, None, None)),

    # From the example document
    ("AV:N/AC:M/Au:N/C:N/I:P/A:N", (4.3, None, None)),
    ("AV:N/AC:L/Au:S/C:P/I:P/A:N", (5.5, None, None)),
    ("AV:N/AC:M/Au:N/C:P/I:N/A:N", (4.3, None, None)),
    ("AV:N/AC:L/Au:S/C:C/I:C/A:C", (9, None, None)),
    ("AV:L/AC:L/Au:N/C:P/I:P/A:P", (4.6, None, None)),
    ("AV:N/AC:M/Au:S/C:C/I:C/A:C", (8.5, None, None)),
    ("AV:N/AC:M/Au:N/C:P/I:P/A:P", (6.8, None, None)),
    ("AV:N/AC:L/Au:N/C:P/I:N/A:N", (5, None, None)),
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", (10, None, None)),
    ("AV:N/AC:L/Au:N/C:N/I:P/A:N", (5, None, None)),
    ("AV:L/AC:M/Au:N/C:C/I:C/A:C", (6.9, None, None)),
    ("AV:N/AC:L/Au:N/C:P/I:N/A:N", (5, None, None)),
    ("AV:N/AC:L/Au:N/C:N/I:P/A:N", (5, None, None)),
    ("AV:A/AC:L/Au:N/C:N/I:C/A:N", (6.1, None, None)),
    ("AV:N/AC:M/Au:N/C:N/I:P/A:N", (4.3, None, None)),
    ("AV:N/AC:M/Au:N/C:C/I:C/A:C", (9.3, None, None)),
    ("AV:A/AC:L/Au:N/C:C/I:C/A:C", (8.3, None, None)),
    ("AV:L/AC:L/Au:N/C:N/I:C/A:N", (4.9, None, None)),
    ("AV:N/AC:M/Au:N/C:P/I:P/A:P", (6.8, None, None)),
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", (10, None, None))
]


def test_v3_vector():
    for vector, results in v3_test_vectors:
        score = calculate_vector(vector, cvss3)

        assert results == score, "Vector {0} failed".format(vector)


def test_v2_vector():
    for vector, results in v2_test_vectors:
        score = calculate_vector(vector, cvss2)

        assert results == score, "Vector {0} failed".format(vector)


def test_cvss_class_mixin():
    # Test that an instance of every enum class is present within each of the state classes

    for cls, module, vectors in [(CVSS2State, cvss2, v2_test_vectors), (CVSS3State, cvss3, v3_test_vectors)]:
        instance = cls()

        enum_classes_in_module = set([x[1] for x in get_enums(module)])
        enum_classes_in_class = set([e[1].__class__ for e in get_enums(instance, only_classes=False)])

        assert enum_classes_in_class == enum_classes_in_module

        # For each test vector we parse it into an instance, then output a vector from that instance.
        # Then we make a new instance and feed that vector into it, then compare that the resulting calculations
        # are all equal.

        for vector, expected in vectors:
            if vector.startswith("CVSS:3.0/"):
                vector = vector.replace("CVSS:3.0/", "")

            vector = "/".join(sorted(vector.split("/")))
            instance = cls()
            instance.from_vector(
                parse_vector(vector, module)
            )

            new_vector = instance.to_vector()

            new_instance = cls()
            new_instance.from_vector(
                parse_vector(new_vector, module)
            )

            assert vector == new_vector

            assert new_instance.debug() == instance.debug()

            assert instance.calculate() == expected
            assert new_instance.calculate() == expected

