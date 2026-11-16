"""The one Anthropic client shared by every module that calls Claude.

Keep a single instance: under Workload Identity Federation each client exchanges the
GitHub OIDC token on its own, and Anthropic accepts each token only once (`jti_reused`),
so a second client would fail until the token file is refreshed.
"""

from __future__ import annotations

from anthropic import Anthropic

client = Anthropic()
