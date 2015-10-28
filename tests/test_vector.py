from cvsslib.vector import parse_vector
from cvsslib import cvss3, cvss2

v3_test_vectors = [
    ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/MAV:A/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N", (4.6, 4.6, 0.0)),
    ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/MAV:A/MAC:L/MPR:N/MUI:N/MS:U/MC:L/MI:N/MA:N", (4.6, 4.6, 4.3)),
    ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/E:H/RL:W/RC:U/CR:H/IR:H/AR:M/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:H/MA:L", (5.8, 5.2, 7.4)),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", (0.0, 0.0, 0.0)),
    ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N", (5.8, 5.8, 7.1)),
    ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:H", (8.2, 8.2, 8.2)),
    ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L/E:U/RL:U/RC:R/CR:M/MPR:L/MUI:R/MI:N/MA:H", (7.7, 6.8, 6.3)),
    ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N/E:P/RL:U/RC:U/CR:H/IR:L/AR:H/MAV:L/MUI:R/MS:C/MC:N/MI:L/MA:N", (5.3, 4.6, 1.3))
]


v2_test_vectors = [
    ("AV:L/AC:M/Au:S/C:N/I:P/A:C/E:U/RL:OF/RC:UR/CDP:N/TD:L/CR:H/IR:H/AR:H", (5, 3.5, 1.2))
]


def test_v3_vector():
    for vector, results in v3_test_vectors:
        score = parse_vector(vector, cvss3)

        assert results == score


def test_v2_vector():
    for vector, results in v2_test_vectors:
        score = parse_vector(vector, cvss2)

        assert results == score
