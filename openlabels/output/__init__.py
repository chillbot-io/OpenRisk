"""
OpenLabels Output Module.

Provides label transport functionality:
- Embedded labels: Write/read labels to/from native file metadata
- Virtual labels: Write/read label pointers to/from extended attributes
- Index: Store and resolve virtual labels

Usage:
    >>> from openlabels.output import read_label, write_label, LabelIndex
    >>>
    >>> # Read a label from any file
    >>> result = read_label("document.pdf")
    >>> if result.label_set:
    ...     print(f"Found {len(result.label_set.labels)} labels")
    >>>
    >>> # Write a label (auto-selects transport)
    >>> success, transport = write_label("data.csv", label_set)
    >>> print(f"Wrote {transport} label")
"""

# Unified reader (primary interface)
from .reader import (
    read_label,
    write_label,
    has_label,
    verify_label,
    get_label_transport,
    rescan_if_stale,
    read_labels_batch,
    find_unlabeled,
    find_stale_labels,
    LabelReadResult,
    read_cloud_label_full,
)

# Embedded label operations
from .embed import (
    supports_embedded_labels,
    read_embedded_label,
    write_embedded_label,
)

# Virtual label operations
from .virtual import (
    read_virtual_label,
    write_virtual_label,
    remove_virtual_label,
    has_virtual_label,
    write_cloud_label,
    read_cloud_label,
)

# Index operations
from .index import (
    LabelIndex,
    get_default_index,
    store_label,
    get_label,
    resolve_pointer,
    DEFAULT_INDEX_PATH,
)

# Report generation
from .report import (
    ReportGenerator,
    ReportSummary,
    results_to_json,
    results_to_csv,
    results_to_html,
    results_to_markdown,
    generate_report,
)

__all__ = [
    # Unified interface
    'read_label',
    'write_label',
    'has_label',
    'verify_label',
    'get_label_transport',
    'rescan_if_stale',
    'read_labels_batch',
    'find_unlabeled',
    'find_stale_labels',
    'LabelReadResult',
    'read_cloud_label_full',

    # Embedded
    'supports_embedded_labels',
    'read_embedded_label',
    'write_embedded_label',

    # Virtual
    'read_virtual_label',
    'write_virtual_label',
    'remove_virtual_label',
    'has_virtual_label',
    'write_cloud_label',
    'read_cloud_label',

    # Index
    'LabelIndex',
    'get_default_index',
    'store_label',
    'get_label',
    'resolve_pointer',
    'DEFAULT_INDEX_PATH',

    # Reports
    'ReportGenerator',
    'ReportSummary',
    'results_to_json',
    'results_to_csv',
    'results_to_html',
    'results_to_markdown',
    'generate_report',
]
