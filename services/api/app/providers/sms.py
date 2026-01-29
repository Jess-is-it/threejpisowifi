from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import SMSLog


class SMSProvider:
    def send(self, db: Session, to_phone: str, message: str) -> None:
        raise NotImplementedError


@dataclass
class MockSMS(SMSProvider):
    provider_name: str = "mock"

    def send(self, db: Session, to_phone: str, message: str) -> None:
        db.add(SMSLog(to_phone=to_phone, message=message, provider=self.provider_name, status="SENT"))
        db.commit()


def get_sms_provider() -> SMSProvider:
    # In production you can add a Smart A2P adapter with env-based credentials.
    # Default is safe for end-to-end demos: it logs messages to the database.
    if settings.sms_provider.lower() == "mock":
        return MockSMS()
    return MockSMS(provider_name="mock")

