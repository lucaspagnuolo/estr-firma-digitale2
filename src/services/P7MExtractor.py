from __future__ import annotations

import logging
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from src.data_class.p7m import ExtractedItem, P7MUnwrapResult
from src.services.Unsigner import Unsigner
from src.utils.safe_zip import UnsafeZipError, ZipLimits, safe_extract_zip

logger = logging.getLogger(__name__)

class P7MExtractionError(RuntimeError):
    """Errore operativo previsto durante la sfirma ricorsiva."""

@dataclass(frozen=True, slots=True)
class ExtractionLimits:
    """Limiti applicati alla sfirma ricorsiva."""

    max_p7m_levels: int = 7
    max_recursion_depth: int = 20
    max_p7m_size: int = 512 * 1024 * 1024


class P7MExtractor:
    """
    Sfirma ricorsivamente file P7M e processa archivi ZIP.

    Gestisce:
    - documento.pdf.p7m
    - documento.pdf.p7m.p7m
    - documento.xml.p7m.p7m
    - archivio.zip.p7m
    - archivio.zip.p7m.p7m
    - documento.zip
    - ZIP contenenti P7M
    - ZIP contenenti altri ZIP
    - P7M contenenti ZIP
    - combinazioni ricorsive dei casi precedenti

    I wrapper P7M non vengono rappresentati nell'albero finale.
    Gli ZIP vengono rappresentati come directory.
    """

    def __init__(
        self,
        limits: ExtractionLimits | None = None,
        zip_limits: ZipLimits | None = None,
    ) -> None:

        self.limits = limits or ExtractionLimits()
        self.zip_limits = zip_limits or ZipLimits()

    @cached_property
    def unsigner(self) -> Unsigner:
        """Crea Unsigner solo quando viene incontrato il primo P7M."""

        logger.debug("Inizializzazione Unsigner")

        return Unsigner()

    def extract(
        self,
        source_path: Path,
        work_dir: Path,
    ) -> P7MUnwrapResult:
        """
        Elabora ricorsivamente il file sorgente.

        Il risultato contiene l'albero logico dei file finali
        e delle directory ricostruite dagli ZIP.
        """

        source_path = Path(source_path).expanduser()
        work_dir = Path(work_dir).expanduser()

        self._validate_source(source_path)

        work_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not work_dir.is_dir():
            raise ValueError(
                f"Working directory non valida: {work_dir}"
            )

        source_path = source_path.resolve()
        work_dir = work_dir.resolve()

        logger.info(
            "Avvio estrazione: %s",
            source_path.name,
        )

        try:
            root = self._process(
                current=source_path,
                work_dir=work_dir,
                recursion_depth=0,
                p7m_level=0,
            )

        except P7MExtractionError as exc:
            logger.error(
                "Elaborazione fallita per %s: %s",
                source_path.name,
                exc,
            )

            root = ExtractedItem(
                name=source_path.name,
                kind="file",
                error=str(exc),
            )

        except OSError as exc:
            logger.exception(
                "Errore filesystem durante l'elaborazione di %s",
                source_path.name,
            )

            root = ExtractedItem(
                name=source_path.name,
                kind="file",
                error=f"Errore filesystem: {exc}",
            )

        logger.info(
            "Estrazione completata: %s",
            source_path.name,
        )

        return P7MUnwrapResult(root=root)

    def _process(
        self,
        current: Path,
        work_dir: Path,
        recursion_depth: int,
        p7m_level: int,
    ) -> ExtractedItem:
        """Determina il tipo di contenuto e lo processa."""

        if recursion_depth > self.limits.max_recursion_depth:
            raise P7MExtractionError(
                "Superata la profondità ricorsiva massima "
                f"di {self.limits.max_recursion_depth}"
            )

        if not current.is_file():
            raise P7MExtractionError(
                f"Il contenuto non è un file regolare: {current}"
            )

        logger.debug(
            "Analisi %s, profondità=%d, livello_p7m=%d",
            current.name,
            recursion_depth,
            p7m_level,
        )

        if current.suffix.casefold() == ".p7m":
            return self._process_p7m(
                current=current,
                work_dir=work_dir,
                recursion_depth=recursion_depth,
                p7m_level=p7m_level,
            )

        try:
            is_zip = zipfile.is_zipfile(current)
        except OSError as exc:
            raise P7MExtractionError(
                f"Impossibile leggere {current.name}: {exc}"
            ) from exc

        if is_zip:
            return self._process_zip(
                current=current,
                work_dir=work_dir,
                recursion_depth=recursion_depth,
                p7m_level=p7m_level,
            )

        return ExtractedItem(
            name=current.name,
            kind="file",
            path=current,
        )

    def _process_p7m(
        self,
        current: Path,
        work_dir: Path,
        recursion_depth: int,
        p7m_level: int,
    ) -> ExtractedItem:
        """Sfirma il P7M e continua ricorsivamente sul payload."""

        next_level = p7m_level + 1

        if next_level > self.limits.max_p7m_levels:
            raise P7MExtractionError(
                "Superato il numero massimo di livelli P7M "
                f"per {current.name}"
            )

        try:
            file_size = current.stat().st_size
        except OSError as exc:
            raise P7MExtractionError(
                f"Impossibile leggere la dimensione di {current.name}"
            ) from exc

        if file_size > self.limits.max_p7m_size:
            raise P7MExtractionError(
                f"File P7M troppo grande: {current.name}"
            )

        payload_dir = Path(
            tempfile.mkdtemp(
                prefix="p7m_",
                dir=work_dir,
            )
        )

        logger.info(
            "Sfirma %s, livello=%d",
            current.name,
            next_level,
        )

        try:
            result = self.unsigner.extract_signed_content(
                current,
                payload_dir,
            )

            if not result:
                raise P7MExtractionError(
                    f"Nessun payload restituito per {current.name}"
                )

            payload = Path(result[0])

            if not payload.is_file():
                raise P7MExtractionError(
                    f"Payload non valido per {current.name}"
                )

            return self._process(
                current=payload,
                work_dir=payload_dir,
                recursion_depth=recursion_depth + 1,
                p7m_level=next_level,
            )

        except P7MExtractionError:
            shutil.rmtree(
                payload_dir,
                ignore_errors=True,
            )
            raise

        except (OSError, ValueError, RuntimeError) as exc:
            shutil.rmtree(
                payload_dir,
                ignore_errors=True,
            )

            raise P7MExtractionError(
                f"Impossibile sfirmare {current.name}: {exc}"
            ) from exc

    def _process_zip(
        self,
        current: Path,
        work_dir: Path,
        recursion_depth: int,
        p7m_level: int,
    ) -> ExtractedItem:
        """Estrae lo ZIP in sicurezza e costruisce il relativo nodo."""

        archive_dir = Path(
            tempfile.mkdtemp(
                prefix="zip_",
                dir=work_dir,
            )
        )

        logger.info(
            "Estrazione ZIP: %s",
            current.name,
        )

        try:
            safe_extract_zip(
                archive_path=current,
                destination=archive_dir,
                limits=self.zip_limits,
            )

            return self._build_directory_node(
                directory=archive_dir,
                logical_name=self._archive_name(current),
                recursion_depth=recursion_depth + 1,
                p7m_level=p7m_level,
            )

        except (
            UnsafeZipError,
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
            OSError,
            RuntimeError,
            NotImplementedError,
        ) as exc:
            shutil.rmtree(
                archive_dir,
                ignore_errors=True,
            )

            raise P7MExtractionError(
                f"Impossibile estrarre lo ZIP "
                f"{current.name}: {exc}"
            ) from exc

    def _build_directory_node(
        self,
        directory: Path,
        logical_name: str,
        recursion_depth: int,
        p7m_level: int,
    ) -> ExtractedItem:
        """Costruisce ricorsivamente l'albero logico della directory."""

        node = ExtractedItem(
            name=logical_name,
            kind="directory",
        )

        try:
            entries = sorted(
                directory.iterdir(),
                key=lambda path: (
                    not path.is_dir(),
                    path.name.casefold(),
                ),
            )

        except OSError as exc:
            node.error = (
                f"Impossibile leggere la directory "
                f"{logical_name}: {exc}"
            )
            return node

        for entry in entries:
            if entry.is_dir():
                child = self._build_directory_node(
                    directory=entry,
                    logical_name=entry.name,
                    recursion_depth=recursion_depth,
                    p7m_level=p7m_level,
                )

                node.children.append(child)
                continue

            if not entry.is_file():
                node.children.append(
                    ExtractedItem(
                        name=entry.name,
                        kind="file",
                        error="Tipo di file non supportato",
                    )
                )
                continue

            try:
                child = self._process(
                    current=entry,
                    work_dir=entry.parent,
                    recursion_depth=recursion_depth,
                    p7m_level=p7m_level,
                )

            except (P7MExtractionError, OSError) as exc:
                logger.error(
                    "Impossibile elaborare %s: %s",
                    entry.name,
                    exc,
                )

                child = ExtractedItem(
                    name=entry.name,
                    kind="file",
                    error=str(exc),
                )

            node.children.append(child)

        return node


    @staticmethod
    def _archive_name(archive: Path) -> str:
        """Restituisce il nome logico della directory generata dallo ZIP."""

        name = archive.name

        if name.casefold().endswith(".zip"):
            name = name[:-4]

        elif (
            not archive.suffix
            and name.casefold().endswith("zip")
        ):
            name = name[:-3]

        return name or "archive"

    @staticmethod
    def _validate_source(
        source_path: Path,
    ) -> None:
        """Valida il file sorgente."""

        if not source_path.exists():
            raise FileNotFoundError(
                f"File sorgente non trovato: {source_path}"
            )

        if not source_path.is_file():
            raise ValueError(
                f"La sorgente non è un file regolare: {source_path}"
            )