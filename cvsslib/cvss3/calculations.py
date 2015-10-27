import math

from .enums import *


def roundup(num):
    return math.ceil(num * 10) / 10


def calculate_exploitability_sub_score(attack_vector: AttackVector,
                                       complexity: AttackComplexity,
                                       privilege: PrivilegeRequired,
                                       interaction: UserInteraction):
    return 8.22 * attack_vector.value * complexity.value * privilege.value * interaction.value


def calculate_modified_exploitability_sub_score(vector: ModifiedAttackVector,
                                                complexity: ModifiedAttackComplexity,
                                                privilege: ModifiedPrivilegeRequired,
                                                interaction: ModifiedUserInteraction):
    return 8.22 * vector.value * complexity.value * privilege.value * interaction.value


def calculate_impact_sub_score(scope: Scope,
                               conf_impact: ConfidentialityImpact,
                               integ_impact: IntegrityImpact,
                               avail_impact: AvailabilityImpact):
    base_impact_sub_score = 1 - ((1 - conf_impact.value) * (1 - integ_impact.value) * (1 - avail_impact.value))

    if scope == scope.UNCHANGED:
        return 6.42 * base_impact_sub_score
    else:
        # What they hell are people smoking...
        return 7.52 * (base_impact_sub_score - 0.029) - 3.25 * math.pow(base_impact_sub_score - 0.02, 15)


def calculate_modified_impact_sub_score(scope: ModifiedScope,
                                        modified_conf: ModifiedConfidentiality,
                                        modified_integ: ModifiedIntegrity,
                                        modified_avail: ModifiedAvailability,
                                        conf_req: ConfidentialityRequirements,
                                        integ_req: IntegrityRequirements,
                                        avail_req: AvailabilityRequirements):
    modified = min(
        1 - (1 - modified_conf.value * conf_req.value) *
        (1 - modified_integ.value * integ_req.value) *
        (1 - modified_avail.value * avail_req.value),
        0.915
    )

    if scope == scope.UNCHANGED:
        return 6.42 * modified
    else:
        return 7.52 * (modified - 0.029) - 3.25 * math.pow(modified - 0.02, 15)


def calculate_base_score(call, scope: Scope, privilege: PrivilegeRequired):
    impact_sub_score = call(calculate_impact_sub_score)

    if impact_sub_score <= 0:
        return 0
    else:

        override = {}
        if scope.CHANGED:
            # Ok, so the privilege enum needs slightly different values depending on the scope. God damn.
            modified_privilege = privilege.extend("ModifiedPrivilegeRequired", {"LOW": 0.68, "HIGH": 0.50})
            privilege = getattr(modified_privilege, privilege.name)
            override[PrivilegeRequired] = privilege

        exploitability_sub_score = call(calculate_exploitability_sub_score, override=override)

        combined_score = impact_sub_score + exploitability_sub_score

        if scope == Scope.CHANGED:
            return roundup(min(1.08 * combined_score, 10))
        else:
            return roundup(min(combined_score, 10))


def calculate_temporal_score(base_score,
                             maturity: ExploitCodeMaturity,
                             remediation: RemediationLevel,
                             confidence: ReportConfidence):
    return roundup(base_score * maturity.value * remediation.value * confidence.value)


def calculate_environmental_score(call,
                                  modified_scope: ModifiedScope,
                                  exploit_code: ExploitCodeMaturity,
                                  remediation: RemediationLevel,
                                  confidence: ReportConfidence,
                                  privilege: ModifiedPrivilegeRequired):
    modified_impact_sub_score = call(calculate_modified_impact_sub_score)

    if modified_impact_sub_score <= 0:
        return 0

    if modified_scope.CHANGED:
        # Ok, so the privilege enum needs slightly different values depending on the scope. God damn.
        modified_privilege = privilege.extend("ModifiedPrivilegeRequired", {"LOW": 0.68, "HIGH": 0.50})
        privilege = getattr(modified_privilege, privilege.name)

    modified_exploitability_sub_score = call(calculate_modified_exploitability_sub_score,
                                             override={ModifiedPrivilegeRequired: privilege})

    if modified_scope == modified_scope.UNCHANGED:
        return roundup(
            roundup(min(modified_impact_sub_score + modified_exploitability_sub_score, 10)) *
            exploit_code.value * remediation.value * confidence.value
        )
    else:
        return roundup(
            roundup(min(1.08 * (modified_impact_sub_score + modified_exploitability_sub_score), 10)) *
            exploit_code.value * remediation.value * confidence.value
        )


def calculate(call):
    base_score = call(calculate_base_score)
    temporal_score = call(calculate_temporal_score, base_score)
    environment_score = call(calculate_environmental_score)

    # impact_subscore = call(calculate_impact_sub_score)
    # exploit_subscore = call(calculate_exploitability_sub_score)
    # mod_impact_subscore = call(calculate_modified_impact_sub_score)

    return base_score, temporal_score, environment_score  # , impact_subscore, exploit_subscore, mod_impact_subscore
