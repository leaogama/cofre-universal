from dataclasses import dataclass
import re


def environment_variable_for_name(name: str) -> str:
    normalized = re.sub(r"[^A-Z0-9_]", "_", name.upper()).strip("_")
    return f"_{normalized}" if normalized[:1].isdigit() else normalized


@dataclass(frozen=True, slots=True)
class Credential:
    id: str
    name: str
    service: str
    project: str
    environment: str
    usage_notes: str
    secret: str
    pending_secret: bool = False

    @property
    def environment_name(self) -> str:
        return environment_variable_for_name(self.name)

    def safe_metadata(self) -> dict[str, str | bool]:
        """Metadados permitidos para catálogos; deliberadamente omite o segredo."""
        return {"id": self.id, "name": self.name, "service": self.service,
                "project": self.project, "environment": self.environment,
                "secret_pending": self.pending_secret}
