from __future__ import annotations

from dataclasses import dataclass

from app.core.config import settings


class PaymentGateway:
    name: str


@dataclass
class MockGateway(PaymentGateway):
    name: str = "mock"


def get_payment_gateway() -> PaymentGateway:
    if settings.payment_provider.lower() == "mock":
        return MockGateway()
    return MockGateway()

