"""The rules that decide how each member is protected."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from ziplet.cli.commands.helpers.passwords.sources import (
    prompt_new_password,
    prompt_password,
)
from ziplet.cli.commands.helpers.selection import glob_matcher
from ziplet.cli.context import Context
from ziplet.cli.errors import UsageError
from ziplet.cli.methods import EncryptionMethod
from ziplet.cli.output import printable
from ziplet.cryptography import ZIP_CRYPTO


@dataclass(eq=False)  # compared by identity: two equal rules are still two rules
class Rule:
    """One line of the plan: members matching *pattern* get *method*.

    *pattern* is ``None`` for the default rule, which matches every member.
    A rule whose password is to be typed keeps its prompt in *prompt* until
    :meth:`EncryptionPlan.resolve_prompts` asks for it; *hint* is what to say
    when there is no terminal to ask at.
    """

    pattern: str | None
    method: EncryptionMethod
    password: bytes | None = None
    prompt: str | None = None
    hint: str | None = None


@dataclass(frozen=True)
class PlanAssignment:
    """The rule chosen for each member (``None``: no rule covers it)."""

    chosen: dict[str, Rule | None]

    @property
    def used(self) -> set[Rule]:
        """Every rule that decides at least one member."""
        return {rule for rule in self.chosen.values() if rule is not None}

    @property
    def methods(self) -> set[EncryptionMethod]:
        return {rule.method for rule in self.chosen.values() if rule is not None}


class EncryptionPlan:
    """An ordered list of :class:`Rule`; the default rule (if any) comes last."""

    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self.rules = list(rules)

    @property
    def methods(self) -> set[EncryptionMethod]:
        return {rule.method for rule in self.rules}

    def assign(self, names: Sequence[str]) -> PlanAssignment:
        """Pick a rule for each of *names*, refusing rules that would do nothing.

        A typo in a pattern must not silently leave files unprotected, so every
        non-default rule has to be the deciding one for at least one member.
        """
        matchers = [
            (rule, None if rule.pattern is None else glob_matcher(rule.pattern))
            for rule in self.rules
        ]
        chosen: dict[str, Rule | None] = {}
        for name in names:
            chosen[name] = next(
                (
                    rule
                    for rule, matches in matchers
                    if matches is None or matches(name)
                ),
                None,
            )
        assignment = PlanAssignment(chosen)
        used = assignment.used
        idle = [
            rule for rule in self.rules if rule.pattern is not None and rule not in used
        ]
        if idle:
            listed = ", ".join(f"'{printable(rule.pattern or '')}'" for rule in idle)
            raise UsageError(
                f"no member is decided by the rule for {listed} (nothing matches, "
                "or an earlier rule already covers everything it matches)",
            )
        return assignment

    def resolve_prompts(
        self,
        assignment: PlanAssignment,
        ctx: Context,
        prompt: Callable[[str], str] = prompt_password,
    ) -> None:
        """Ask for the passwords of the used rules that are still missing one."""
        used = assignment.used
        for rule in self.rules:
            if rule.prompt is not None and rule.password is None and rule in used:
                rule.password = prompt_new_password(
                    rule.prompt,
                    ctx,
                    hint=rule.hint,
                    prompt=prompt,
                )


def warn_if_weak(methods: Iterable[EncryptionMethod], ctx: Context) -> None:
    if any(method.scheme == ZIP_CRYPTO for method in methods):
        ctx.warn(
            "ZipCrypto is a weak legacy cipher; prefer aes256 "
            "unless a tool needs ZipCrypto"
        )
