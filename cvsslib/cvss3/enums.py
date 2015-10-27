from .. import BaseEnum


# Taken from https://www.first.org/cvss/specification-document#i8.4

# Exploitability metrics
class AttackVector(BaseEnum):
    """
    Vector: AV
    Mandatory: yes
    """
    NETWORK = 0.85
    ADJACENT_NETWORK = 0.62
    LOCAL = 0.55
    PHYSICAL = 0.2


class AttackComplexity(BaseEnum):
    """
    Vector: AC
    Mandatory: yes
    """
    LOW = 0.77
    HIGH = 0.44


class PrivilegeRequired(BaseEnum):
    """
    Vector: PR
    Mandatory: yes
    """
    NONE = 0.85
    LOW = 0.62
    HIGH = 0.27


class UserInteraction(BaseEnum):
    """
    Vector: UI
    Mandatory: yes
    """
    NONE = 0.85
    REQUIRED = 0.62


class Scope(BaseEnum):
    """
    Vector: S
    Mandatory: yes
    """
    UNCHANGED = 0
    CHANGED = 1


# Impacts
class ConfidentialityImpact(BaseEnum):
    """
    Vector: C
    Mandatory: yes
    """
    HIGH = 0.56
    LOW = 0.22
    NONE = 0


class IntegrityImpact(BaseEnum):
    """
    Vector: I
    Mandatory: yes
    """
    HIGH = 0.56
    LOW = 0.22
    NONE = 0


class AvailabilityImpact(BaseEnum):
    """
    Vector: A
    Mandatory: yes
    """
    HIGH = 0.56
    LOW = 0.22
    NONE = 0


# Temporal metrics
class ExploitCodeMaturity(BaseEnum):
    """
    Vector: E
    """
    NOT_DEFINED = 1
    HIGH = 1
    FUNCTIONAL = 0.97
    PROOF_OF_CONCEPT = 0.94
    UNPROVEN = 0.91


class RemediationLevel(BaseEnum):
    """
    Vector: RL
    """
    NOT_DEFINED = 1
    UNAVAILABLE = 1
    WORKAROUND = 0.97
    TEMPORARY_FIX = 0.96
    OFFICIAL_FIX = 0.95


class ReportConfidence(BaseEnum):
    """
    Vector: RC
    """
    NOT_DEFINED = 1
    CONFIRMED = 1
    REASONABLE = 0.96
    UNKNOWN = 0.92


class ConfidentialityRequirements(BaseEnum):
    """
    Vector: CR
    """
    NOT_DEFINED = 1
    HIGH = 1.5
    MEDIUM = 1
    LOW = 0.5


class IntegrityRequirements(BaseEnum):
    """
    Vector: IR
    """
    NOT_DEFINED = 1
    HIGH = 1.5
    MEDIUM = 1
    LOW = 0.5


class AvailabilityRequirements(BaseEnum):
    """
    Vector: AR
    """
    NOT_DEFINED = 1
    HIGH = 1.5
    MEDIUM = 1
    LOW = 0.5


ModifiedAttackVector = AttackVector.extend("ModifiedAttackVector", {"NOT_DEFINED": 0.85}, "Vector: MAV")

ModifiedAttackComplexity = AttackComplexity.extend("ModifiedAttackComplexity", {"NOT_DEFINED": 0.77}, "Vector: MAC")

ModifiedPrivilegeRequired = PrivilegeRequired.extend("ModifiedPrivilegesRequired", {"NOT_DEFINED": 0.85}, "Vector: MPR")

ModifiedUserInteraction = UserInteraction.extend("ModifiedUserInteraction", {"NOT_DEFINED": 0.85}, "Vector: MUI")

ModifiedScope = Scope.extend("ModifiedScope", {"NOT_DEFINED": Scope.UNCHANGED.value}, "Vector: MS")

ModifiedConfidentiality = ConfidentialityImpact.extend("ModifiedConfidentiality", {"NOT_DEFINED": 1.0}, "Vector: MC")

ModifiedIntegrity = IntegrityImpact.extend("ModifiedIntegrity", {"NOT_DEFINED": 1.0}, "Vector: MI")

ModifiedAvailability = AvailabilityImpact.extend("ModifiedAvailability", {"NOT_DEFINED": 1.0}, "Vector: MA")
