import zipfile
from pathlib import Path

from src.data_class.p7m import P7MSignatureLevel, P7MUnwrapResult
from src.services.Unsigner import Unsigner

import logging
logger = logging.getLogger(__name__)


class P7MExtractor:
    """
    Estrae ricorsivamente file P7M e archivi ZIP.

    Casi coperti:

    - documento.pdf.p7m
    - documento.pdf.p7m.p7m
    - documento.xml.p7m.p7m
    - archivio.zip.p7m.p7m
    - documento.zip.p7m
    - documentozip.p7m
    - documento.zip -> file.p7m
    - documento.zip -> file.p7m.p7m
    - documento.zip -> directory/file.p7m
    - documento.zip -> archivio.zip -> file.p7m
    - documento.zip -> file.p7m -> archivio.zip
    - archivio.zip.p7m -> archivio.zip -> file.p7m

    Ogni contenuto estratto viene nuovamente analizzato:

    - P7M: estrazione del payload e prosecuzione ricorsiva;
    - ZIP: estrazione dei membri e prosecuzione ricorsiva;
    - altro: restituzione del file finale.

    Il risultato contiene:

    - il file finale estratto, se l'input conduce a un singolo file;
    - la directory radice estratta, se viene incontrato uno ZIP;
    - l'elenco di tutti i livelli di firma P7M incontrati.

    La working directory viene utilizzata esclusivamente per
    materializzare i contenuti necessari all'estrazione.
    """

    MAX_P7M_LEVELS = 7

    def __init__(
        self,
        tsl_file: Path,
        trust_pem: Path,
    ) -> None:
        self.tsl_file = tsl_file
        self.trust_pem = trust_pem

    def extract(
        self,
        source_path: Path,
        work_dir: Path,
    ) -> P7MUnwrapResult:
        """
        Avvia l'estrazione ricorsiva.

        Args:
            source_path:
                File iniziale da analizzare.

            work_dir:
                Directory tecnica utilizzata per materializzare
                temporaneamente i contenuti estratti.

        Returns:
            Risultato dell'estrazione contenente il payload finale
            e l'elenco dei livelli di firma rilevati.
        """
        source_path = Path(source_path)
        work_dir = Path(work_dir)

        work_dir.mkdir(parents=True, exist_ok=True)

        result = P7MUnwrapResult()

        result.payload = self._extract_recursive(
            current=source_path,
            work_dir=work_dir,
            result=result,
            p7m_level=0,
        )

        return result

    def _extract_recursive(
        self,
        current: Path,
        work_dir: Path,
        result: P7MUnwrapResult,
        p7m_level: int,
    ) -> Path | None:
        """
        Determina il tipo del contenuto e applica la relativa estrazione.
        """
        if not current.exists():
            logger.warning("File non trovato: %s", current)
            return None

        if current.suffix.lower() == ".p7m":
            return self._extract_p7m(
                current=current,
                work_dir=work_dir,
                result=result,
                p7m_level=p7m_level,
            )

        if current.is_file() and zipfile.is_zipfile(current):
            return self._extract_zip(
                current=current,
                work_dir=work_dir,
                result=result,
            )

        return current

    def _extract_p7m(
        self,
        current: Path,
        work_dir: Path,
        result: P7MUnwrapResult,
        p7m_level: int,
    ) -> Path | None:
        """
        Estrae un P7M, registra il relativo livello di firma e continua
        ricorsivamente sul payload ottenuto.
        """
        next_level = p7m_level + 1

        if next_level > self.MAX_P7M_LEVELS:
            logger.warning(
                "Raggiunto il limite massimo di %s livelli P7M per %s",
                self.MAX_P7M_LEVELS,
                current,
            )
            return None

        unsigner = Unsigner(
            self.tsl_file,
            self.trust_pem,
        )

        payload, signer, valid = unsigner.extract_signed_content(
            current,
            work_dir,
        )

        if not payload:
            logger.warning(
                "Impossibile estrarre il payload dal file P7M: %s",
                current,
            )
            return None

        payload = Path(payload)
        payload = self._correct_zip_name(payload)

        result.signatures.append(
            P7MSignatureLevel(
                level=next_level,
                source=str(current),
                payload=str(payload),
                signer=signer,
                valid=valid,
            )
        )

        return self._extract_recursive(
            current=payload,
            work_dir=work_dir,
            result=result,
            p7m_level=next_level,
        )

    def _extract_zip(
        self,
        current: Path,
        work_dir: Path,
        result: P7MUnwrapResult,
    ) -> Path:
        """
        Estrae uno ZIP nella working directory.

        Ogni file contenuto nell'archivio viene analizzato ricorsivamente.
        La directory radice dell'archivio estratto viene restituita come
        payload, preservando così la struttura originaria.
        """
        archive_work_dir = self._build_archive_work_dir(
            current=current,
            work_dir=work_dir,
        )
        archive_work_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(current) as archive:
            self._safe_extract_all(
                archive=archive,
                destination=archive_work_dir,
            )

        extracted_files = [
            path
            for path in archive_work_dir.rglob("*")
            if path.is_file()
        ]

        for extracted_file in extracted_files:
            self._extract_recursive(
                current=extracted_file,
                work_dir=extracted_file.parent,
                result=result,
                p7m_level=0,
            )

        return archive_work_dir

    @staticmethod
    def _correct_zip_name(payload: Path) -> Path:
        """
        Corregge il caso:

            documentozip.p7m -> documentozip

        trasformandolo in:

            documento.zip

        La correzione viene applicata esclusivamente quando il payload
        è realmente un archivio ZIP.
        """
        if (
            not payload.suffix
            and payload.name.lower().endswith("zip")
            and zipfile.is_zipfile(payload)
        ):
            corrected = payload.with_name(
                f"{payload.name[:-3]}.zip"
            )

            if corrected.exists() and corrected != payload:
                raise FileExistsError(
                    "Impossibile correggere il nome del payload perché "
                    f"il file esiste già: {corrected}"
                )

            payload.rename(corrected)
            return corrected

        return payload

