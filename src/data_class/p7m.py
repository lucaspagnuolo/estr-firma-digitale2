from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass(slots=True)
class ExtractedItem:
    """
    Elemento prodotto dalla sfirma ricorsiva.

    Un elemento può rappresentare:

    - un file finale sfirmato;
    - una directory ottenuta dall'estrazione di uno ZIP.

    `path` è valorizzato soltanto per i file finali.
    `children` è utilizzato soltanto per le directory.

    Il ricostruttore può riprodurre la gerarchia attraversando
    ricorsivamente `children` e copiando ogni `path` con il relativo
    `name`.
    """

    name: str
    kind: Literal["file", "directory"]
    path: Path | None = None
    children: list["ExtractedItem"] = field(default_factory=list)
    error: str | None = None

    @property
    def successful(self) -> bool:
        """Indica se l'elemento e tutti i suoi figli sono validi."""
        return (
            self.error is None
            and all(child.successful for child in self.children)
        )


@dataclass(slots=True)
class P7MUnwrapResult:
    """
    Risultato della sfirma ricorsiva.

    `root` rappresenta la struttura logica da passare al ricostruttore.
    """

    root: ExtractedItem