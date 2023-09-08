"""The module used to genetate incidents data based on intrusion sets"""
import logging
import math
import random
from math import ceil
from typing import List

import numpy
from scipy.stats import betabinom
from scipy.stats.sampling import DiscreteAliasUrn

from attribution_tools.parsers import AttackPattern, IntrusionSet, Malware, Tool

logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def generate_incident_size(lbound: int, ubound: int) -> int:
    """Generate the size of incident based on"""
    alpha, beta = 1.5, 10.0

    region_size = ceil(ubound - lbound)
    assert region_size > 0, f"Wrong bound arguments: {lbound}, {ubound}"

    percent_point_func = numpy.arange(
        betabinom.ppf(0.0, region_size, alpha, beta), betabinom.ppf(1.0, region_size, alpha, beta)
    )
    random_variable = betabinom(region_size, alpha, beta)

    pmf_values = random_variable.pmf(percent_point_func).tolist()
    generator = DiscreteAliasUrn(pmf_values, random_state=numpy.random.default_rng())

    return (generator.rvs(size=1) + lbound)[0]


class IncidentGenerator:
    """Class in used to create incident based on intrusion set."""

    # expected size of an incident (lower and upper bounds)
    N_SIZE_MIN, N_SIZE_MAX = 10, 50
    # fraction taken by attack patterns
    FRAC_ATTACK_PATTERN = 0.5
    # fraction taken by tools
    FRAC_TOOLS = 0.2
    # fraction taken by malware
    FRAC_MALWARE = 0.2
    # fraction taken by other elements
    FRAC_OTHER = 0.1

    def generate(self, source: IntrusionSet) -> list:
        """Generation of the incident content."""
        content = []
        n_size_max = sum(
            [
                len(source.attack_patterns),
                len(source.malwares),
                len(source.tools),
                len(source.indicators),
                len(source.identities),
                len(source.locations),
                len(source.vulnerabilities),
            ]
        )
        if n_size_max < self.N_SIZE_MIN:
            n_size_max = self.N_SIZE_MIN

        n_size = generate_incident_size(self.N_SIZE_MIN, self.N_SIZE_MAX)
        n_size = min(n_size, n_size_max)

        content.extend(self.sample_attack_patterns(source.attack_patterns, n_size))
        content.extend(self.sample_tools(source.tools, n_size))
        content.extend(self.sample_malwares(source.malwares, n_size))
        other_entities = source.indicators + source.vulnerabilities + source.identities + source.locations
        content.extend(self.sample_others(other_entities, n_size))

        return content

    def sample_attack_patterns(self, source: List[AttackPattern], max_incident_size) -> List[str]:
        """Creates the sample list of attack patterns."""
        result = []
        if source:
            n_max_attack_patterns = math.ceil(max_incident_size * self.FRAC_ATTACK_PATTERN)
            selection = set(random.choices(source, k=n_max_attack_patterns))
            result.extend([item.semantic_id for item in selection])
        return result

    def sample_tools(self, source: List[Tool], max_incident_size) -> List[str]:
        """Creates the sample list of tools."""
        result = []
        if source:
            n_max_tools = math.ceil(max_incident_size * self.FRAC_TOOLS)
            selection = set(random.choices(source, k=n_max_tools))
            result.extend([item.semantic_id for item in selection])
        return result

    def sample_malwares(self, source: List[Malware], max_incident_size) -> List[str]:
        """Creates the sample list of malwares."""
        result = []
        if source:
            n_max_malwares = math.ceil(max_incident_size * self.FRAC_MALWARE)
            selection = set(random.choices(source, k=n_max_malwares))
            result.extend([item.semantic_id for item in selection])
        return result

    def sample_others(self, source: list, max_incident_size) -> List[str]:
        """Creates the sample list of other STIX2 entities."""
        result = []
        if source:
            n_max_others = math.ceil(max_incident_size * self.FRAC_OTHER)
            selection = random.sample(source, min(len(source), n_max_others))  # do note the difference of this method
            result.extend([item.semantic_id for item in selection])
        return result
