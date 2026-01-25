"""
OpenLabels Client.

High-level API for scoring files and objects.
"""

from typing import List, Optional, Union
from pathlib import Path

from .adapters.base import Adapter, NormalizedInput
from .core.scorer import ScoringResult


class Client:
    """
    High-level OpenLabels client.

    Example usage:
        >>> from openlabels import Client
        >>> from openlabels.adapters import MacieAdapter
        >>>
        >>> client = Client()
        >>> result = client.score(
        ...     adapters=[MacieAdapter()],
        ...     findings=macie_findings,
        ...     metadata=s3_metadata,
        ... )
        >>> print(f"Risk score: {result.score} ({result.tier})")
    """

    def score_file(
        self,
        path: Union[str, Path],
        adapters: Optional[List[Adapter]] = None,
    ) -> ScoringResult:
        """
        Score a local file.

        If no adapters specified, uses the built-in scanner.

        Args:
            path: Path to file
            adapters: Optional list of adapters to use

        Returns:
            ScoringResult with score and breakdown
        """
        # TODO: Implement
        raise NotImplementedError("File scoring not yet implemented")

    def score_from_adapters(
        self,
        inputs: List[NormalizedInput],
    ) -> ScoringResult:
        """
        Score from pre-extracted adapter outputs.

        Use this when you've already run adapters and have normalized inputs.

        Args:
            inputs: List of NormalizedInput from adapters

        Returns:
            ScoringResult with score and breakdown
        """
        # TODO: Merge inputs if multiple, then score
        raise NotImplementedError("Adapter scoring not yet implemented")
