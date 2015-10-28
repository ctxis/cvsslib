import math

from .enums import *
from decimal import Decimal as D

EXPLOITABILITY_COEFFECIENT = D("8.22")
IMPACT_UNCHANGED_COEFFECIENT = D("6.42")
IMPACT_CHANGED_COEFFECIENT = D("7.52")


def roundup(num):
    return D(math.ceil(num * 10) / 10)


def calculate_exploitability_sub_score(attack_vector: AttackVector,
                                       complexity: AttackComplexity,
                                       privilege: PrivilegeRequired,
                                       interaction: UserInteraction):
    return EXPLOITABILITY_COEFFECIENT * attack_vector.value * complexity.value * privilege.value * interaction.value


def calculate_modified_exploitability_sub_score(vector: ModifiedAttackVector,
                                                complexity: ModifiedAttackComplexity,
                                                privilege: ModifiedPrivilegeRequired,
                                                interaction: ModifiedUserInteraction):
    return EXPLOITABILITY_COEFFECIENT * vector.value * complexity.value * privilege.value * interaction.value


def calculate_impact_sub_score(scope: Scope,
                               conf_impact: ConfidentialityImpact,
                               integ_impact: IntegrityImpact,
                               avail_impact: AvailabilityImpact):
    base_impact_sub_score = 1 - ((1 - conf_impact.value) * (1 - integ_impact.value) * (1 - avail_impact.value))

    if scope == scope.UNCHANGED:
        return IMPACT_UNCHANGED_COEFFECIENT * base_impact_sub_score
    else:
        # What they hell are people smoking...
        return IMPACT_CHANGED_COEFFECIENT *\
               (base_impact_sub_score - D("0.029")) -\
               D("3.25") * D(math.pow(base_impact_sub_score - D("0.02"), 15))


def calculate_modified_impact_sub_score(scope: ModifiedScope,
                                        modified_conf: ModifiedConfidentialityImpact,
                                        modified_integ: ModifiedIntegrityImpact,
                                        modified_avail: ModifiedAvailabilityImpact,
                                        conf_req: ConfidentialityRequirement,
                                        integ_req: IntegrityRequirement,
                                        avail_req: AvailabilityRequirement):
    modified = min(
        1 -
        (1 - modified_conf.value * conf_req.value) *
        (1 - modified_integ.value * integ_req.value) *
        (1 - modified_avail.value * avail_req.value),
        0.915
    )

    if scope == scope.UNCHANGED:
        return IMPACT_UNCHANGED_COEFFECIENT * modified
    else:
        return IMPACT_CHANGED_COEFFECIENT * (modified - D("0.029")) - D("3.25") * D(math.pow(modified - D(0.02), 15))


def calculate_base_score(run_calculation, scope: Scope, privilege: PrivilegeRequired):
    impact_sub_score = run_calculation(calculate_impact_sub_score)

    if impact_sub_score <= 0:
        return 0
    else:

        override = {}
        if scope == scope.CHANGED:
            # Ok, so the privilege enum needs slightly different values depending on the scope. God damn.
            modified_privilege = privilege.extend("PrivilegeRequired", {"LOW": D("0.68"), "HIGH": D("0.50")})
            privilege = getattr(modified_privilege, privilege.name)
            override[PrivilegeRequired] = privilege

        exploitability_sub_score = run_calculation(calculate_exploitability_sub_score, override=override)

        combined_score = impact_sub_score + exploitability_sub_score

        if scope == Scope.CHANGED:
            return roundup(min(D("1.08") * combined_score, 10))
        else:
            return roundup(min(combined_score, 10))


def calculate_temporal_score(base_score,
                             maturity: ExploitCodeMaturity,
                             remediation: RemediationLevel,
                             confidence: ReportConfidence):
    return roundup(base_score * maturity.value * remediation.value * confidence.value)


def calculate_environmental_score(run_calculation,
                                  modified_scope: ModifiedScope,
                                  exploit_code: ExploitCodeMaturity,
                                  remediation: RemediationLevel,
                                  confidence: ReportConfidence,
                                  privilege: ModifiedPrivilegeRequired):

    modified_impact_sub_score = run_calculation(calculate_modified_impact_sub_score)

    if modified_impact_sub_score <= 0:
        return 0

    if modified_scope == modified_scope.CHANGED:
        # Ok, so the privilege enum needs slightly different values depending on the scope. God damn.
        modified_privilege = privilege.extend("ModifiedPrivilegeRequired", {"LOW": D("0.68"), "HIGH": D("0.50")})
        privilege = getattr(modified_privilege, privilege.name)

    modified_exploitability_sub_score = run_calculation(calculate_modified_exploitability_sub_score,
                                                        override={ModifiedPrivilegeRequired: privilege})

    if modified_scope == modified_scope.UNCHANGED:
        return roundup(
            roundup(min(modified_impact_sub_score + modified_exploitability_sub_score, 10)) *
            exploit_code.value * remediation.value * confidence.value
        )
    else:
        return roundup(
            roundup(min(D("1.08") * (modified_impact_sub_score + modified_exploitability_sub_score), 10)) *
            exploit_code.value * remediation.value * confidence.value
        )


def calculate(run_calculation, get):
    base_score = run_calculation(calculate_base_score)
    temporal_score = run_calculation(calculate_temporal_score, base_score)

    override = {}

    for optional_enum in OPTIONAL_VALUES:
        set_value = get(optional_enum)

        if set_value == optional_enum.NOT_DEFINED:
            # Override the value with the non-optional one
            parent_enum_class = optional_enum._parent
            parent_enum_value = get(parent_enum_class)
            override[optional_enum] = getattr(optional_enum, parent_enum_value.name)

    environment_score = run_calculation(calculate_environmental_score, override=override)

    return base_score, temporal_score, environment_score