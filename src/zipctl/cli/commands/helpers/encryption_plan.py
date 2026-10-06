"""The rules that decide how each member is protected."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from zipctl.cli.commands.helpers.passwords import (
    prompt_new_password,
)
from zipctl.cli.commands.helpers.selection import name_matcher
from zipctl.cli.context import Context
from zipctl.cli.errors import UsageError
from zipctl.cli.methods import NO_ENCRYPTION, EncryptionMethod
from zipctl.cli.output import printable
from zipctl.cryptography import ZIP_CRYPTO
from zipctl.zipfile.file import ZipFileExtra


@dataclass(frozen=True)
class Protection:
    """How one member is written: its encryption method, password and AES settings."""

    method: EncryptionMethod = NO_ENCRYPTION
    password: bytes | None = None
    extra: ZipFileExtra | None = None


UNPROTECTED = Protection()


def protection_for(
    method: EncryptionMethod, password: bytes | None, aes_version: int | None
) -> Protection:
    """The protection that writes with *method*, its *password* and AES version."""
    if not method.is_encrypted:
        return UNPROTECTED
    extra = None
    if method.is_aes:
        extra = ZipFileExtra(
            force_wz_aes_version=aes_version, wz_aes_nbits=method.aes_bits
        )
    return Protection(method, password, extra)


@dataclass(frozen=True, eq=False)  # by identity: two equal rules are still two
class Rule:
    """One line of the plan: members matching *pattern* get *method*.

    *pattern* is ``None`` for the default rule, which matches every member.
    A rule whose password is to be typed has its *prompt*, asked the first
    time a member's protection is needed; *hint* is what to say when there
    is no terminal to ask at.
    """

    pattern: str | None
    method: EncryptionMethod
    password: bytes | None = None
    prompt: str | None = None
    hint: str | None = None


class PlanAssignment:
    """The rule chosen for each member (``None``: no rule covers it)."""

    def __init__(self, plan: EncryptionPlan, chosen: dict[str, Rule | None]) -> None:
        self.chosen: dict[str, Rule | None] = chosen
        self._plan: EncryptionPlan = plan
        self._typed: dict[Rule, bytes] | None = None

    @property
    def used(self) -> set[Rule]:
        """Every rule that decides at least one member."""
        return {rule for rule in self.chosen.values() if rule is not None}

    @property
    def methods(self) -> set[EncryptionMethod]:
        return {rule.method for rule in self.used}

    def protection(self, name: str, ctx: Context) -> Protection:
        """How member *name* is written.

        The first call asks, in rule order, for every password still to be typed.
        """
        rule = self.chosen[name]
        if rule is None:
            return UNPROTECTED
        if self._typed is None:
            self._typed = self._ask(ctx)
        password = rule.password or self._typed.get(rule)
        return protection_for(rule.method, password, self._plan.wz_aes_version)

    def _ask(self, ctx: Context) -> dict[Rule, bytes]:
        used = self.used
        return {
            rule: prompt_new_password(rule.prompt, ctx, hint=rule.hint)
            for rule in self._plan.rules
            if rule.prompt is not None and rule.password is None and rule in used
        }


class EncryptionPlan:
    """An ordered list of :class:`Rule`; the default rule (if any) comes last."""

    def __init__(
        self, rules: Iterable[Rule] = (), wz_aes_version: int | None = None
    ) -> None:
        self.rules: list[Rule] = list(rules)
        self.wz_aes_version: int | None = wz_aes_version

    @property
    def methods(self) -> set[EncryptionMethod]:
        return {rule.method for rule in self.rules}

    def assign(self, names: Sequence[str], ctx: Context) -> PlanAssignment:
        """Pick a rule for each of *names*, refusing rules that would do nothing.

        A typo in a pattern must not silently leave files unprotected, so every
        non-default rule has to be the deciding one for at least one member.
        """
        matchers = [
            (rule, None if rule.pattern is None else name_matcher(rule.pattern))
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
        assignment = PlanAssignment(self, chosen)
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
        _warn_if_weak(assignment.methods, ctx)
        return assignment


def _warn_if_weak(methods: Iterable[EncryptionMethod], ctx: Context) -> None:
    if any(method.scheme == ZIP_CRYPTO for method in methods):
        ctx.output.warn(
            "ZipCrypto is a weak legacy cipher; prefer aes256 "
            "unless a tool needs ZipCrypto"
        )
