import pytest

from cvsslib import cvss2, cvss3, parse_vector
from cvsslib.vector import sorted_vector
from .cvss_scores import v3_test_vectors, v2_test_vectors
from django_app.app.models import v2Model, v3Model


@pytest.mark.django_db
def test_models():
    for vectors, module, model in [
        (v3_test_vectors, cvss3, v3Model),  (v2_test_vectors, cvss2, v2Model)
    ]:
        for vector, expected in vectors:
            vector = sorted_vector(vector)
            inst = model()
            inst.from_vector(
                parse_vector(vector, module)
            )
            inst.save()

            assert inst.calculate() == expected
            assert inst.to_vector() == vector
