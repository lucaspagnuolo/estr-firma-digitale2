from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class P7MSignatureLevel:
    """Descrive un singolo livello di firma P7M."""

    level: int
    source: str
    payload: str
    signer: str | None
    valid: bool


@dataclass
class P7MUnwrapResult:
    """
    Risultato dell'estrazione ricorsiva.

    `payload` può rappresentare:

    - il file finale estratto;
    - la directory radice ottenuta dall'estrazione di uno ZIP.

    La struttura delle directory prodotte viene preservata e costituisce
    la rappresentazione ricostruibile del contenuto originario.
    """

    payload: Path | None = None
    signatures: list[P7MSignatureLevel] = field(default_factory=list)