"""Pattern-based detectors for PHI/PII entity recognition."""

import os

from .detector import PatternDetector as _StandardPatternDetector

# Hyperscan acceleration is available but disabled by default due to
# compilation overhead (~7-14s on first use). Enable with environment variable.
# When enabled, provides 2-3x speedup on pattern matching.
_USE_HYPERSCAN = os.environ.get('OPENLABELS_USE_HYPERSCAN', '').lower() in ('1', 'true', 'yes')

if _USE_HYPERSCAN:
    try:
        from .hyperscan_detector import HyperscanDetector, _HYPERSCAN_AVAILABLE
        if _HYPERSCAN_AVAILABLE:
            PatternDetector = HyperscanDetector
        else:
            PatternDetector = _StandardPatternDetector
    except ImportError:
        PatternDetector = _StandardPatternDetector
else:
    PatternDetector = _StandardPatternDetector

__all__ = ["PatternDetector"]
