from .. import BaseEnum


# Taken from https://www.first.org/cvss/v2/guide#i3.2.1

class AccessVector(BaseEnum):
    LOCAL_ACCESS = 0.395
    ADJACENT_NETWORK = 0.646
    NETWORK_ACCESSIBLE = 1


class AccessComplexity(BaseEnum):
    HIGH = 0.35
    MEDIUM = 0.61
    LOW = 0.71


class Authentication(BaseEnum):
    MULTIPLE = 0.45
    SINGLE = 0.56
    NONE = 0.704


class ConfidentialityImpact(BaseEnum):
    NONE = 0
    PARTIAL = 0.275
    COMPLETE = 0.660


class IntegrityImpact(BaseEnum):
    NONE = 0
    PARTIAL = 0.275
    COMPLETE = 0.660


class AvailabilityImpact(BaseEnum):
    NONE = 0
    PARTIAL = 0.275
    COMPLETE = 0.660


# Temporal:
class Exploitability(BaseEnum):
    UNPROVEN = 0.85
    PROOF_OF_CONCEPT = 0.9
    FUNCTIONAL = 0.95
    HIGH = 1
    NOT_DEFINED = 1


class RemediationLevel(BaseEnum):
    OFFICIAL_FIX = 0.87
    TEMPORARY_FIX = 0.90
    WORKAROUND = 0.95
    UNAVAILABLE = 1
    NOT_DEFINED = 1


class ReportConfidence(BaseEnum):
    UNCONFIRMED = 0.9
    UNCORROBORATED = 0.95
    CONFIRMED = 1
    NOT_DEFINED = 1


# Environmental
class CollateralDamagePotential(BaseEnum):
    NONE = 0
    LOW = 0.1
    LOW_MEDIUM = 0.3
    MEDIUM_HIGH = 0.4
    HIGH = 0.5
    NOT_DEFINED = 0


class TargetDistribution(BaseEnum):
    NONE = 0
    LOW = 0.25
    MEDIUM = 0.75
    HIGH = 1
    NOT_DEFINED = 1


class ConfidentialityRequirement(BaseEnum):
    LOW = 0.5
    MEDIUM = 1
    HIGH = 1.51
    NOT_DEFINED = 1


class IntegrityRequirement(BaseEnum):
    LOW = 0.5
    MEDIUM = 1
    HIGH = 1.51
    NOT_DEFINED = 1


class AvailabilityRequirement(BaseEnum):
    LOW = 0.5
    MEDIUM = 1.0
    HIGH = 1.51
    NOT_DEFINED = 1.0
