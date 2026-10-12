"""Graph interface only. NetworkX is available for teammate 1's future work."""

from typing import Protocol

from agentguard_contracts import AgentCapabilities, CapabilityGraph


class GraphBuilder(Protocol):
    def build(self, capabilities: list[AgentCapabilities]) -> CapabilityGraph:
        """Keep declared capabilities separate from observed runtime evidence."""
        ...
