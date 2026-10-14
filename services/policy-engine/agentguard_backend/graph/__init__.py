"""Stable graph protocol; implementation lives in projector/repository/analyzer.

Unpaired capability lists are selectors/summary, never an action/resource product.
"""

from typing import Protocol

from agentguard_contracts import AgentCapabilities, CapabilityGraph


class GraphBuilder(Protocol):
    def build(self, capabilities: list[AgentCapabilities]) -> CapabilityGraph:
        """Keep declared capabilities separate from observed runtime evidence."""
        ...
