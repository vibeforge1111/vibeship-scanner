"""
Vibeship Scanner - False Positive Feedback System

This module handles privacy-preserving collection of false positive feedback
to help improve scanner rules based on real-world usage patterns.
"""

from .sanitizer import (
    CodeSanitizer,
    ConsentLevel,
    SanitizedReport,
    sanitize_for_feedback
)

__all__ = [
    'CodeSanitizer',
    'ConsentLevel',
    'SanitizedReport',
    'sanitize_for_feedback'
]
