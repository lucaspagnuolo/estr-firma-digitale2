from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import NamedTuple

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


class UnsignerError(RuntimeError):
    """Errore base del componente Unsigner."""


class SignedContentExtractionError(UnsignerError):
    """Errore durante l'estrazione di un contenuto firmato."""


class OpenSSLExecutionError(UnsignerError):
    """Errore durante l'esecuzione di OpenSSL."""


class OpenSSLTimeoutError(OpenSSLExecutionError):
    """Timeout durante l'esecuzione di OpenSSL."""


class ExtractionResult(NamedTuple):
    """
    Risultato dell'estrazione di un file firmato.

    ``certificate_temporally_valid`` indica esclusivamente che il
    certificato si trova nell'intervallo temporale notBefore/notAfter.
    """

    payload_path: Path
    signer: str
    certificate_temporally_valid: bool


class Unsigner:
    """
    Estrae il contenuto da file CMS/PKCS#7.

    L'estrazione utilizza OpenSSL con l'opzione ``-noverify``.
    Viene quindi verificata l'integrità crittografica del contenuto,
    ma non viene validata la catena di trust del certificato.

    La validità temporale restituita da ``extract_signed_content``
    indica solamente che il certificato è compreso nell'intervallo
    notBefore/notAfter.
    """

    OPENSSL_TIMEOUT_SECONDS = 60
    MAX_LOG_OUTPUT_LENGTH = 2_000
    MAX_P7M_SIZE_BYTES = 100 * 1024 * 1024

    def __init__(
        self,
        *,
        openssl_executable: str | Path | None = None,
    ) -> None:
        """
        Inizializza il componente di estrazione.

        Args:
            openssl_executable:
                Percorso opzionale dell'eseguibile OpenSSL. Se non
                specificato, viene cercato automaticamente nel PATH.

        Raises:
            OpenSSLExecutionError:
                Se OpenSSL non viene trovato.
        """
        if openssl_executable is not None:
            self.openssl_executable = str(openssl_executable)
            return

        detected_openssl = shutil.which("openssl")

        if detected_openssl is None:
            raise OpenSSLExecutionError(
                "OpenSSL non è installato oppure non è presente nel PATH."
            )

        self.openssl_executable = detected_openssl

    @classmethod
    def _truncate(cls, value: str | None) -> str:
        """Limita la dimensione di un valore destinato ai log."""
        if not value:
            return ""

        normalized = value.strip()

        if len(normalized) <= cls.MAX_LOG_OUTPUT_LENGTH:
            return normalized

        return (
            normalized[: cls.MAX_LOG_OUTPUT_LENGTH]
            + "...[truncated]"
        )

    @staticmethod
    def _safe_unlink(path: Path | None) -> None:
        """
        Elimina un file temporaneo senza mascherare eventuali eccezioni
        applicative già in corso.
        """
        if path is None:
            return

        try:
            path.unlink(missing_ok=True)
        except OSError:
            logger.warning(
                "Impossibile eliminare un file temporaneo. "
                "event=unsigner.cleanup_failed file=%s",
                path.name,
                exc_info=True,
            )

    @staticmethod
    def _is_non_empty_file(path: Path) -> bool:
        """Restituisce True se il percorso è un file non vuoto."""
        try:
            return path.is_file() and path.stat().st_size > 0
        except OSError:
            return False

    @staticmethod
    def _validate_input_file(
        path: Path,
        *,
        description: str,
        max_size_bytes: int,
    ) -> None:
        """Valida esistenza, tipo e dimensione di un file di input."""
        if not path.exists():
            raise FileNotFoundError(
                f"{description} non trovato: {path}"
            )

        if not path.is_file():
            raise ValueError(
                f"Il percorso indicato non è un file: {path}"
            )

        try:
            file_size = path.stat().st_size
        except OSError as exc:
            raise UnsignerError(
                f"Impossibile determinare la dimensione del file: {path}"
            ) from exc

        if file_size == 0:
            raise ValueError(
                f"{description} vuoto: {path}"
            )

        if file_size > max_size_bytes:
            raise ValueError(
                f"{description} troppo grande: {file_size} byte. "
                f"Dimensione massima consentita: {max_size_bytes} byte."
            )

    @staticmethod
    def _ensure_destination_available(path: Path) -> None:
        """Impedisce la sovrascrittura silenziosa di un output esistente."""
        if path.exists():
            raise SignedContentExtractionError(
                "Il file di output esiste già e non verrà sovrascritto: "
                f"{path}"
            )

    def _run_openssl(
        self,
        arguments: list[str],
        *,
        operation: str,
    ) -> subprocess.CompletedProcess[str]:
        """
        Esegue OpenSSL senza shell e con timeout.

        Un return code diverso da zero viene restituito al chiamante per
        permettere la gestione del fallback CMS/S/MIME.
        """
        command = [self.openssl_executable, *arguments]
        started_at = monotonic()

        logger.debug(
            "Avvio OpenSSL. "
            "event=unsigner.openssl_started operation=%s",
            operation,
        )

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.OPENSSL_TIMEOUT_SECONDS,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            raise OpenSSLTimeoutError(
                "OpenSSL ha superato il timeout di "
                f"{self.OPENSSL_TIMEOUT_SECONDS} secondi durante "
                f"l'operazione '{operation}'."
            ) from exc

        except (FileNotFoundError, OSError) as exc:
            raise OpenSSLExecutionError(
                "Impossibile avviare OpenSSL durante "
                f"l'operazione '{operation}'."
            ) from exc

        duration_ms = round(
            (monotonic() - started_at) * 1_000
        )

        logger.debug(
            "OpenSSL terminato. "
            "event=unsigner.openssl_completed "
            "operation=%s returncode=%s duration_ms=%s stderr=%s",
            operation,
            result.returncode,
            duration_ms,
            self._truncate(result.stderr),
        )

        return result

    def _extract_with_cms(
        self,
        p7m_path: Path,
        temporary_output: Path,
    ) -> bool:
        """Tenta l'estrazione mediante il comando OpenSSL CMS."""
        result = self._run_openssl(
            [
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                str(p7m_path),
                "-noverify",
                "-out",
                str(temporary_output),
            ],
            operation="estrazione CMS",
        )

        return (
            result.returncode == 0
            and self._is_non_empty_file(temporary_output)
        )

    def _extract_with_smime(
        self,
        p7m_path: Path,
        temporary_output: Path,
    ) -> bool:
        """Tenta l'estrazione mediante il fallback OpenSSL S/MIME."""
        self._safe_unlink(temporary_output)

        result = self._run_openssl(
            [
                "smime",
                "-verify",
                "-inform",
                "DER",
                "-in",
                str(p7m_path),
                "-noverify",
                "-out",
                str(temporary_output),
            ],
            operation="estrazione S/MIME",
        )

        return (
            result.returncode == 0
            and self._is_non_empty_file(temporary_output)
        )

    @staticmethod
    def _is_pdf(path: Path) -> bool:
        """Riconosce un PDF tramite la firma binaria iniziale."""
        try:
            with path.open("rb") as file:
                return file.read(4) == b"%PDF"
        except OSError as exc:
            raise SignedContentExtractionError(
                f"Impossibile leggere il contenuto estratto: {path}"
            ) from exc

    @classmethod
    def _get_payload_destination(
        cls,
        p7m_path: Path,
        out_dir: Path,
        temporary_output: Path,
    ) -> Path:
        """
        Determina il nome dell'output.

        Viene rimosso un solo suffisso ``.p7m``. Questo mantiene il nesting
        necessario per l'estrazione ricorsiva:

        - documento.pdf.p7m -> documento.pdf
        - documento.pdf.p7m.p7m -> documento.pdf.p7m
        - archivio.zip.p7m.p7m -> archivio.zip.p7m
        """
        destination = out_dir / p7m_path.stem

        if (
            cls._is_pdf(temporary_output)
            and destination.suffix.lower() != ".pdf"
        ):
            destination = destination.with_suffix(".pdf")

        return destination

    @staticmethod
    def _load_embedded_certificates(
        p7m_path: Path,
    ) -> list[x509.Certificate]:
        """
        Legge i certificati incorporati nel contenitore PKCS#7.

        I certificati vengono letti esclusivamente per ricavare alcune
        informazioni descrittive. Non vengono usati per validare la
        catena di trust.
        """
        try:
            raw_data = p7m_path.read_bytes()
        except OSError:
            logger.warning(
                "Impossibile leggere i certificati incorporati. "
                "event=unsigner.certificate_container_read_failed "
                "file=%s",
                p7m_path.name,
            )
            return []

        try:
            return pkcs7.load_der_pkcs7_certificates(raw_data)
        except ValueError:
            try:
                return pkcs7.load_pem_pkcs7_certificates(raw_data)
            except ValueError:
                logger.warning(
                    "Nessun certificato PKCS#7 leggibile. "
                    "event=unsigner.certificate_parse_failed file=%s",
                    p7m_path.name,
                )
                return []

    @classmethod
    def _read_certificate_info(
        cls,
        p7m_path: Path,
    ) -> tuple[str, bool]:
        """
        Legge il Common Name e la validità temporale del primo
        certificato incorporato.

        Il booleano restituito indica esclusivamente se il certificato
        è compreso nell'intervallo notBefore/notAfter. Non rappresenta
        la validità complessiva della firma.
        """
        certificates = cls._load_embedded_certificates(p7m_path)

        if not certificates:
            return "Sconosciuto", False

        certificate = certificates[0]

        common_names = certificate.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )

        signer = (
            common_names[0].value.strip()
            if common_names and common_names[0].value.strip()
            else "Sconosciuto"
        )

        try:
            not_before = certificate.not_valid_before_utc
            not_after = certificate.not_valid_after_utc
        except AttributeError:
            # Compatibilità con versioni meno recenti di cryptography.
            not_before = certificate.not_valid_before.replace(
                tzinfo=timezone.utc
            )
            not_after = certificate.not_valid_after.replace(
                tzinfo=timezone.utc
            )

        now = datetime.now(timezone.utc)
        temporally_valid = not_before <= now <= not_after

        return signer, temporally_valid

    def extract_signed_content(
        self,
        p7m_path: Path,
        out_dir: Path,
    ) -> ExtractionResult:
        """
        Estrae il contenuto di un file P7M.

        Il metodo tenta prima CMS e usa S/MIME come fallback.
        Non sovrascrive eventuali file già esistenti.

        Returns:
            ExtractionResult contenente:
            - percorso del contenuto estratto;
            - Common Name del primo certificato incorporato;
            - validità temporale del certificato.

        Raises:
            FileNotFoundError:
                Se il file P7M non esiste.
            ValueError:
                Se l'input non è un file valido.
            SignedContentExtractionError:
                Se il contenuto non può essere estratto.
            OpenSSLExecutionError:
                Se OpenSSL non può essere eseguito.
            OpenSSLTimeoutError:
                Se OpenSSL supera il timeout.
        """
        p7m_path = Path(p7m_path)
        out_dir = Path(out_dir)

        self._validate_input_file(
            p7m_path,
            description="File firmato",
            max_size_bytes=self.MAX_P7M_SIZE_BYTES,
        )

        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SignedContentExtractionError(
                f"Impossibile creare la directory di output: {out_dir}"
            ) from exc

        logger.info(
            "Avvio estrazione P7M. "
            "event=unsigner.extraction_started file=%s",
            p7m_path.name,
        )

        temporary_output: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=out_dir,
                prefix=".unsigner-payload-",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_output = Path(temporary_file.name)

            cms_ok = self._extract_with_cms(
                p7m_path,
                temporary_output,
            )

            if cms_ok:
                extraction_method = "cms"
            else:
                logger.warning(
                    "Estrazione CMS fallita, avvio fallback S/MIME. "
                    "event=unsigner.cms_fallback file=%s",
                    p7m_path.name,
                )

                smime_ok = self._extract_with_smime(
                    p7m_path,
                    temporary_output,
                )

                if not smime_ok:
                    raise SignedContentExtractionError(
                        "Impossibile estrarre il contenuto firmato da "
                        f"'{p7m_path.name}'."
                    )

                extraction_method = "smime"

            destination = self._get_payload_destination(
                p7m_path,
                out_dir,
                temporary_output,
            )

            self._ensure_destination_available(destination)

            try:
                # Il temporaneo è nella stessa directory, quindi il rename
                # finale rimane sullo stesso filesystem.
                temporary_output.replace(destination)
                temporary_output = None
            except OSError as exc:
                raise SignedContentExtractionError(
                    "Impossibile finalizzare il contenuto estratto: "
                    f"{destination}"
                ) from exc

            signer, temporally_valid = self._read_certificate_info(
                p7m_path
            )

            logger.info(
                "Estrazione P7M completata. "
                "event=unsigner.extraction_completed "
                "input=%s output=%s method=%s "
                "signer=%s certificate_temporally_valid=%s",
                p7m_path.name,
                destination.name,
                extraction_method,
                signer,
                temporally_valid,
            )

            return ExtractionResult(
                payload_path=destination,
                signer=signer,
                certificate_temporally_valid=temporally_valid,
            )

        except UnsignerError:
            logger.error(
                "Estrazione P7M non completata. "
                "event=unsigner.extraction_failed file=%s",
                p7m_path.name,
                exc_info=True,
            )
            raise

        except OSError as exc:
            logger.error(
                "Errore di filesystem durante l'estrazione. "
                "event=unsigner.extraction_io_failed file=%s",
                p7m_path.name,
                exc_info=True,
            )

            raise SignedContentExtractionError(
                f"Errore durante l'estrazione di '{p7m_path.name}'."
            ) from exc

        finally:
            self._safe_unlink(temporary_output)