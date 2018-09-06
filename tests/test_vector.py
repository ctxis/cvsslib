from cvsslib.vector import calculate_vector
from cvsslib import CVSS2State, CVSS3State,  cvss3, cvss2
from cvsslib.utils import get_enums
from cvsslib.example_vectors import v3_vectors, v2_vectors
import pathlib
import pytest

data_dir = pathlib.Path(__file__).parent / "files"


def split_vector(line):
    vector, rest = line.split(" - ", 1)
    rest = rest.replace("(", "").replace(")", "").strip().split(", ")
    score = (float(rest[0]),
             float(rest[1]) if rest[1] != 'None' else None,
             float(rest[2]) if rest[2] != 'None' else None)

    return vector, score


@pytest.mark.parametrize('line', (data_dir / 'vectors_simple3').read_text().splitlines())
def test_v3_vector_files_simple3(line):
    vector, score = split_vector(line)
    parsed = calculate_vector(vector, cvss3)
    assert parsed == score


@pytest.mark.parametrize('line', (data_dir / 'vectors_random3').read_text().splitlines())
def test_v3_vector_files_random3(line):
    vector, score = split_vector(line)
    parsed = calculate_vector(vector, cvss3)
    assert parsed == score


@pytest.mark.parametrize('line', (data_dir / 'vectors_random2').read_text().splitlines())
def test_v3_vector_files_random2(line):
    vector, score = split_vector(line)
    parsed = calculate_vector(vector, cvss2)
    assert parsed == score


@pytest.mark.parametrize('line', (data_dir / 'vectors_simple2').read_text().splitlines())
def test_v3_vector_files_random2(line):
    vector, score = split_vector(line)
    parsed = calculate_vector(vector, cvss2)
    assert parsed == score


@pytest.mark.parametrize('vector, results', v3_vectors)
def test_v3_vector(vector, results):
    score = calculate_vector(vector, cvss3)
    assert results == score, "Vector {0} failed".format(vector)


@pytest.mark.parametrize('vector, results', v2_vectors)
def test_v2_vector(vector, results):
    score = calculate_vector(vector, cvss2)
    assert results == score, "Vector {0} failed".format(vector)


@pytest.mark.parametrize('vector, expected', v2_vectors)
def test_mixin_vectors_v2(vector, expected):
    instance = CVSS2State()
    instance.from_vector(vector)
    new_vector = instance.to_vector()

    new_instance = CVSS2State()
    new_instance.from_vector(new_vector)
    assert vector == new_vector
    assert new_instance.debug() == instance.debug()
    assert instance.calculate() == expected
    assert new_instance.calculate() == expected


@pytest.mark.parametrize('vector, expected', v3_vectors)
def test_mixin_vectors_v3(vector, expected):
    instance = CVSS3State()
    instance.from_vector(vector)
    new_vector = instance.to_vector()

    new_instance = CVSS3State()
    new_instance.from_vector(new_vector)
    assert vector == new_vector
    assert new_instance.debug() == instance.debug()
    assert instance.calculate() == expected
    assert new_instance.calculate() == expected


@pytest.mark.parametrize('cls,module', ((CVSS3State, cvss3), (CVSS2State, cvss2)))
def test_cvss_class_mixin(cls, module):
    # Test that an instance of every enum class is present within each of the state classes
    instance = cls()
    enum_classes_in_module = set([x[1] for x in get_enums(module)])
    enum_classes_in_class = set([e[1].__class__ for e in get_enums(instance, only_classes=False)])
    assert enum_classes_in_class == enum_classes_in_module
