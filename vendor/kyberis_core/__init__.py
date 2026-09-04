"""Reusable client for the Kyberis Threat Investigator API.

One transport and one endpoint/tool map, shared by every Kyberis API consumer
so integrations do not drift into subtly diverging copies. Pure standard
library with no runtime dependencies, so it can be vendored into host runtimes
that cannot install packages.
"""

from __future__ import annotations

from .client import KyberisClient, KyberisClientError, RequestResult
from .config import DEFAULT_API_PREFIX, KyberisClientConfig
from .tool_schemas import (
    ASSESSMENT_TYPES,
    CLAIM_TYPES,
    ENTITY_TYPES,
    RELATIONSHIP_TYPES,
    THREAT_INVESTIGATION_GUIDE,
    TOOL_SPECS,
    ToolSpec,
    threat_investigation_guide,
    tool_by_name,
)

__all__ = [
    "KyberisClient",
    "KyberisClientError",
    "RequestResult",
    "KyberisClientConfig",
    "DEFAULT_API_PREFIX",
    "ToolSpec",
    "TOOL_SPECS",
    "tool_by_name",
    "threat_investigation_guide",
    "THREAT_INVESTIGATION_GUIDE",
    "CLAIM_TYPES",
    "ENTITY_TYPES",
    "RELATIONSHIP_TYPES",
    "ASSESSMENT_TYPES",
]

__version__ = "0.1.0"
