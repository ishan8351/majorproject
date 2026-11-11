"""
IaC Parser package for RegRadar.
"""

from regradar.parser.hcl_parser import HCLParser
from regradar.parser.reference_extractor import ReferenceExtractor
from regradar.parser.module_resolver import (
    ModuleResolver,
    ResolvedModule,
    ModuleOutput,
    ModuleVariable,
)

__all__ = [
    "HCLParser",
    "ReferenceExtractor",
    "ModuleResolver",
    "ResolvedModule",
    "ModuleOutput",
    "ModuleVariable",
]
