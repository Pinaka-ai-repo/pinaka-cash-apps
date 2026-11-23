"""Exact Currency Minor-Unit Arithmetic, FX Rate Policy & Accounting Bridge Invariants.

Enforces:
- SEC-24: Exact integer minor-unit arithmetic across 0-, 2-, and 3-decimal ISO 4217 currencies.
- Receipt Bridge Identity: gross_minor == net_minor + fee_minor and net_minor == applied_minor + unapplied_minor.
- Deductions are open AR residuals, never counted as received cash.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP

CURRENCY_EXPONENTS: dict[str, int] = {
    "USD": 2,
    "EUR": 2,
    "GBP": 2,
    "INR": 2,
    "AED": 2,
    "CAD": 2,
    "AUD": 2,
    "CHF": 2,
    "SGD": 2,
    "JPY": 0,
    "KRW": 0,
    "KWD": 3,
    "BHD": 3,
    "OMR": 3,
}


def get_currency_exponent(currency: str) -> int:
    code = currency.strip().upper()
    if code not in CURRENCY_EXPONENTS:
        raise ValueError(f"Unsupported or unknown ISO 4217 currency code: '{currency}'")
    return CURRENCY_EXPONENTS[code]


@dataclass(frozen=True)
class MoneyMinor:
    amount_minor: int
    currency: str
    exponent: int

    def __init__(self, amount_minor: int, currency: str) -> None:
        if isinstance(amount_minor, float) or not isinstance(amount_minor, int):
            raise TypeError("SEC-24 violation: Monetary amounts must be integer minor units, never floats.")
        code = currency.strip().upper()
        exp = get_currency_exponent(code)
        object.__setattr__(self, "amount_minor", amount_minor)
        object.__setattr__(self, "currency", code)
        object.__setattr__(self, "exponent", exp)

    @classmethod
    def from_decimal_str(cls, amount_str: str, currency: str) -> "MoneyMinor":
        code = currency.strip().upper()
        exp = get_currency_exponent(code)
        dec = Decimal(amount_str.strip())
        scale = Decimal(10) ** exp
        minor = int((dec * scale).to_integral_exact(rounding=ROUND_HALF_UP))
        return cls(minor, code)

    def to_decimal(self) -> Decimal:
        scale = Decimal(10) ** self.exponent
        return Decimal(self.amount_minor) / scale

    def format_tabular(self) -> str:
        val = self.to_decimal()
        if self.exponent == 0:
            return f"{self.currency} {int(val):,}"
        return f"{self.currency} {val:,.{self.exponent}f}"

    def _require_same_currency(self, other: "MoneyMinor") -> None:
        if self.currency != other.currency:
            raise ValueError(f"SEC-24 currency mismatch: '{self.currency}' vs '{other.currency}'")

    def __add__(self, other: "MoneyMinor") -> "MoneyMinor":
        self._require_same_currency(other)
        return MoneyMinor(self.amount_minor + other.amount_minor, self.currency)

    def __sub__(self, other: "MoneyMinor") -> "MoneyMinor":
        self._require_same_currency(other)
        return MoneyMinor(self.amount_minor - other.amount_minor, self.currency)


@dataclass(frozen=True)
class ApprovedFXRate:
    from_currency: str
    to_currency: str
    rate_decimal: Decimal
    rate_source: str
    effective_date: str
    approved_by: str

    def convert(self, money: MoneyMinor) -> MoneyMinor:
        if money.currency != self.from_currency:
            raise ValueError(f"FX source currency '{self.from_currency}' does not match '{money.currency}'")
        if self.rate_decimal <= Decimal("0"):
            raise ValueError("FX rate must be positive")
        target_exp = get_currency_exponent(self.to_currency)
        major_in = money.to_decimal()
        major_out = major_in * self.rate_decimal
        scale_out = Decimal(10) ** target_exp
        minor_out = int((major_out * scale_out).to_integral_exact(rounding=ROUND_HALF_UP))
        return MoneyMinor(minor_out, self.to_currency)


def verify_receipt_accounting_bridge(
    *,
    gross_minor: int,
    fee_minor: int,
    net_minor: int,
    applied_cash_minor: int,
    unapplied_cash_minor: int,
) -> None:
    """Enforces ASTRA accounting bridge invariants on every receipt and posting intent."""
    for name, val in (
        ("gross_minor", gross_minor),
        ("fee_minor", fee_minor),
        ("net_minor", net_minor),
        ("applied_cash_minor", applied_cash_minor),
        ("unapplied_cash_minor", unapplied_cash_minor),
    ):
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise ValueError(f"SEC-24 violation: '{name}' must be a non-negative integer minor unit (got {val!r}).")

    if gross_minor != net_minor + fee_minor:
        raise ValueError(
            f"SEC-24 bridge failure: gross ({gross_minor}) != net ({net_minor}) + fee ({fee_minor})."
        )
    if net_minor != applied_cash_minor + unapplied_cash_minor:
        raise ValueError(
            f"SEC-24 bridge failure: net receipt ({net_minor}) != applied cash ({applied_cash_minor}) + unapplied cash ({unapplied_cash_minor})."
        )
