from .enums import *
from cvsslib.base_enum import NotDefined


def calculate_impact(conf: ConfidentialityImpact,
                     integ: IntegrityImpact,
                     avail: AvailabilityImpact):
    # Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
    return D("10.41") * \
           (1 -
            (1 - conf) *
            (1 - integ) *
            (1 - avail))


def calculate_exploitability(access: AccessVector,
                             complexity: AccessComplexity,
                             auth: Authentication):
    # Exploitability = 20* AccessVector*AccessComplexity*Authentication
    return D("20") * access * complexity * auth


def calculate_base_score(run_calculation, impact_function):
    # BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
    # f(impact)= 0 if Impact=0, 1.176 otherwise
    impact = run_calculation(impact_function)
    exploitability = run_calculation(calculate_exploitability)

    result = (D("0.6") * impact) + (D("0.4") * exploitability) - D("1.5")
    f_impact = 0 if impact == 0 else D("1.176")

    return round(result * f_impact, 1)


# emporalScore = round_to_1_decimal(BaseScore*Exploitability*RemediationLevel*ReportConfidence)
def calculate_temporal_score(base_score,
                             exploit: Exploitability,
                             remediation: RemediationLevel,
                             confidence: ReportConfidence):
    return round(base_score * exploit * remediation * confidence, 1)


# AdjustedImpact = min(10,10.41*(1-(1-ConfImpact*ConfReq)*(1-IntegImpact*IntegReq)*(1-AvailImpact*AvailReq)))
def calculate_adjusted_impact(conf_impact: ConfidentialityImpact,
                              conf_req: ConfidentialityRequirement,
                              integ_impact: IntegrityImpact,
                              integ_req: IntegrityRequirement,
                              avail_impact: AvailabilityImpact,
                              avail_req: AvailabilityRequirement):
    return min(
        10,
        D("10.41") * (
            1 - (
                (1 - conf_impact * conf_req) *
                (1 - integ_impact * integ_req) *
                (1 - avail_impact * avail_req)
            )
        )
    )


# EnvironmentalScore = round_to_1_decimal((AdjustedTemporal+(10-AdjustedTemporal)
#   *CollateralDamagePotential)*TargetDistribution)
#
# AdjustedTemporal = TemporalScore recomputed with the BaseScores Impact sub-equation
#   replaced with the AdjustedImpact equation
def calculate_environmental_score(run_calculation,
                                  collat_damage: CollateralDamagePotential,
                                  target_dist: TargetDistribution):
    adjusted_base_score = run_calculation(calculate_base_score, calculate_adjusted_impact)
    adjusted_temporal = run_calculation(calculate_temporal_score, adjusted_base_score)

    return round(
        (adjusted_temporal +
         (10 - adjusted_temporal) *
         collat_damage) *
        target_dist, 1
    )


def calculate(run_calculation, get):
    # We pass `calculate_impact` here because we need to pass a different impact function while computing the
    # environmental score
    base_score = run_calculation(calculate_base_score, calculate_impact)

    temporal_metrics = {get(Exploitability), get(RemediationLevel), get(ReportConfidence)}
    if all(isinstance(e.value, NotDefined) for e in temporal_metrics):
        temporal_score = None
    else:
        temporal_score = float(run_calculation(calculate_temporal_score, base_score))

    environment_metrics = {get(cls) for cls in ENVIRONMENTAL_METRICS}
    if all(isinstance(e.value, NotDefined) for e in environment_metrics):
        environmental_score = None
    else:
        environmental_score = float(run_calculation(calculate_environmental_score))

    return float(base_score), temporal_score, environmental_score
