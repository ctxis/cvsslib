from cvsslib.vector import calculate_vector, parse_vector, sorted_vector
from cvsslib import CVSS2State, CVSS3State,  cvss3, cvss2
from cvsslib.utils import get_enums
from .cvss_scores import v3_test_vectors, v2_test_vectors


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
            vector = sorted_vector(vector)

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

