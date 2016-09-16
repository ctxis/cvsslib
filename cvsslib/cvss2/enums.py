from decimal import Decimal as D
from cvsslib.base_enum import BaseEnum, NotDefined


# Taken from https://www.first.org/cvss/v2/guide#i3.2.1

class AccessVector(BaseEnum):
    """
    Vector: AV
    """
    LOCAL_ACCESS = D("0.395")
    ADJACENT_NETWORK = D("0.646")
    NETWORK_ACCESSIBLE = D("1")


class AccessComplexity(BaseEnum):
    """
    Vector: AC
    """
    HIGH = D("0.35")
    MEDIUM = D("0.61")
    LOW = D("0.71")


class Authentication(BaseEnum):
    """
    Vector: Au
    """
    MULTIPLE = D("0.45")
    SINGLE = D("0.56")
    NONE = D("0.704")


class ConfidentialityImpact(BaseEnum):
    """
    Vector: C
    """
    NONE = D("0")
    PARTIAL = D("0.275")
    COMPLETE = D("0.660")


class IntegrityImpact(BaseEnum):
    """
    Vector: I
    """
    NONE = D("0")
    PARTIAL = D("0.275")
    COMPLETE = D("0.660")


class AvailabilityImpact(BaseEnum):
    """
    Vector: A
    """
    NONE = D("0")
    PARTIAL = D("0.275")
    COMPLETE = D("0.660")


# Temporal:
class Exploitability(BaseEnum):
    """
    Vector: E
    """
    UNPROVEN = D("0.85")
    PROOF_OF_CONCEPT = D("0.9")
    FUNCTIONAL = D("0.95")
    HIGH = D("1")
    NOT_DEFINED = NotDefined(D("1"))

    _vectors = {
        "poc": "PROOF_OF_CONCEPT"
    }


class RemediationLevel(BaseEnum):
    """
    Vector: RL
    """
    OFFICIAL_FIX = D("0.87")
    TEMPORARY_FIX = D("0.90")
    WORKAROUND = D("0.95")
    UNAVAILABLE = D("1")
    NOT_DEFINED = NotDefined(D("1"))

    _vectors = {
        "of": "OFFICIAL_FIX",
        "tf": "TEMPORARY_FIX"
    }


class ReportConfidence(BaseEnum):
    """
    Vector: RC
    """
    UNCONFIRMED = D("0.9")
    UNCORROBORATED = D("0.95")
    CONFIRMED = D("1")
    NOT_DEFINED = NotDefined(D("1"))

    _vectors = {
        "uc": "UNCONFIRMED",
        "ur": "UNCORROBORATED"
    }


# Environmental
class CollateralDamagePotential(BaseEnum):
    """
    Vector: CDP
    """
    NONE = D("0")
    LOW = D("0.1")
    LOW_MEDIUM = D("0.3")
    MEDIUM_HIGH = D("0.4")
    HIGH = D("0.5")
    NOT_DEFINED = NotDefined(D("0"))

    _vectors = {
        "lm": "LOW_MEDIUM",
        "mh": "MEDIUM_HIGH"
    }


class TargetDistribution(BaseEnum):
    """
    Vector: TD
    """
    NONE = D("0")
    LOW = D("0.25")
    MEDIUM = D("0.75")
    HIGH = D("1")
    NOT_DEFINED = NotDefined(D("1"))


class ConfidentialityRequirement(BaseEnum):
    """
    Vector: CR
    """
    LOW = D("0.5")
    MEDIUM = D("1")
    HIGH = D("1.51")
    NOT_DEFINED = NotDefined(D("1"))


class IntegrityRequirement(BaseEnum):
    """
    Vector: IR
    """
    LOW = D("0.5")
    MEDIUM = D("1")
    HIGH = D("1.51")
    NOT_DEFINED = NotDefined(D("1"))


class AvailabilityRequirement(BaseEnum):
    """
    Vector: AR
    """
    LOW = D("0.5")
    MEDIUM = D("1.0")
    HIGH = D("1.51")
    NOT_DEFINED = NotDefined(D("1.0"))


ENVIRONMENTAL_METRICS = {
    CollateralDamagePotential,
    TargetDistribution,
    ConfidentialityRequirement,
    IntegrityRequirement,
    AvailabilityRequirement
}

ORDERING = (
    AccessVector,
    AccessComplexity,
    Authentication,

    ConfidentialityImpact,
    IntegrityImpact,
    AvailabilityImpact,

    Exploitability,
    RemediationLevel,
    ReportConfidence,

    CollateralDamagePotential,
    TargetDistribution,

    ConfidentialityRequirement,
    IntegrityRequirement,
    AvailabilityRequirement
)