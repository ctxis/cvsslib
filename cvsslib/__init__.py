from .mixin import cvss_mixin
from . import cvss3, cvss2


def make_display_name(str):
    return " ".join(
        s.capitalize() for s in str.lower().split("_")
    )


class CVSS2State(metaclass=cvss_mixin(cvss2)):
    pass


class CVSS3State(metaclass=cvss_mixin(cvss3)):
    pass


