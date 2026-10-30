from __future__ import annotations

import logging
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from src.data_class.p7m import ExtractedItem, P7MUnwrapResult

logger = logging.getLogger(__name__)

class ZipCreator:
    """
    Crea uno ZIP dalla struttura prodotta dallo sfirmatore.

    Le directory e i file vengono ricostruiti seguendo
    ricorsivamente i nodi `ExtractedItem`.
    """

    def __call__(
        self,
        result: P7MUnwrapResult,
        output_filename: str,
    ) -> Path:
        """
        Crea e restituisce lo ZIP finale.

        Raises:
            ValueError:
                Se il risultato contiene errori o nodi non validi.
        """
        logger.info("Creazione ZIP: %s", output_filename)

        if result.root.error:
            logger.error(
                "Errore nel nodo root: %s",
                result.root.error,
            )
            raise ValueError(
                f"Risultato non ricostruibile: {result.root.error}"
            )

        if not output_filename.casefold().endswith(".zip"):
            output_filename += ".zip"

        out_dir = Path(tempfile.mkdtemp(prefix="zip_out_"))
        zip_path = out_dir / Path(output_filename).name

        try:
            with zipfile.ZipFile(
                zip_path,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                self._write_item(
                    archive=archive,
                    item=result.root,
                    parent=PurePosixPath(),
                    include_name=result.root.kind == "file",
                )

        except Exception:
            logger.exception(
                "Errore durante la creazione dello ZIP"
            )
            zip_path.unlink(missing_ok=True)
            raise

        logger.info("ZIP creato: %s", zip_path)

        return zip_path

    def _write_item(
        self,
        archive: zipfile.ZipFile,
        item: ExtractedItem,
        parent: PurePosixPath,
        include_name: bool = True,
    ) -> None:
        """Scrive ricorsivamente un elemento nello ZIP."""

        logger.debug(
            "Elaborazione: name=%s kind=%s",
            item.name,
            item.kind,
        )

        if item.error:
            logger.error(
                "Elemento non ricostruibile %s: %s",
                item.name,
                item.error,
            )
            raise ValueError(
                f"Elemento non ricostruibile {item.name}: {item.error}"
            )

        current = parent / item.name if include_name else parent

        if item.kind == "file":
            if item.path is None or not item.path.is_file():
                logger.error(
                    "File non disponibile: %s",
                    item.name,
                )
                raise ValueError(
                    f"File non disponibile: {item.name}"
                )

            logger.debug(
                "Aggiunta file allo ZIP: %s -> %s",
                item.path,
                current,
            )

            archive.write(
                item.path,
                current.as_posix(),
            )
            return

        if item.kind != "directory":
            logger.error(
                "Tipo elemento non supportato: %s",
                item.kind,
            )
            raise ValueError(
                f"Tipo elemento non supportato: {item.kind}"
            )

        if not item.children and current.parts:
            logger.debug(
                "Aggiunta directory vuota: %s",
                current,
            )

            archive.writestr(
                current.as_posix().rstrip("/") + "/",
                b"",
            )
            return

        for child in item.children:
            self._write_item(
                archive=archive,
                item=child,
                parent=current,
            )
