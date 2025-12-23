"""
Vibeship Scanner - False Positive Feedback System

PRIVACY-FIRST DESIGN:
- We NEVER store actual code - only structural patterns
- We NEVER store identifiable information
- Users can preview EXACTLY what gets sent before submission
"""

from .sanitizer import (
    CodeSanitizer,
    ConsentLevel,
    SanitizedReport,
    sanitize_for_feedback,
    preview_feedback
)

__all__ = [
    'CodeSanitizer',
    'ConsentLevel',
    'SanitizedReport',
    'sanitize_for_feedback',
    'preview_feedback'
]
