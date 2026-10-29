import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET


logger = logging.getLogger(__name__)

class TrustStoreError(RuntimeError):
    """Errore durante la costruzione del trust store."""

class SignedContentExtractionError(RuntimeError):
    """Errore durante l'estrazione di un contenuto firmato."""

class OpenSSLExecutionError(RuntimeError):
    """Errore durante l'esecuzione di OpenSSL."""


class Unsigner:
    def __init__(
        self,
        tsl_path: Path,
        out_pem: Path,
    ) -> None:
        self.tsl_path = Path(tsl_path)
        self.out_pem = Path(out_pem)

        self.ns = {
            "tsl": "http://uri.etsi.org/02231/v2#",
            "ds": "http://www.w3.org/2000/09/xmldsig#",
        }

    @staticmethod
    def _run_openssl(
        arguments: list[str],
        *,
        operation: str,
    ) -> subprocess.CompletedProcess[str]:
        """
        Esegue un comando OpenSSL.

        Il metodo non solleva eccezioni in caso di return code diverso
        da zero, così da permettere al chiamante di gestire eventuali
        fallback applicativi.

        Raises:
            OpenSSLExecutionError:
                Se OpenSSL non è installato o il processo non può
                essere avviato.
        """
        command = ["openssl", *arguments]

        logger.debug(
            "Esecuzione OpenSSL. operation=%s command=%s",
            operation,
            command,
        )

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            logger.exception(
                "OpenSSL non è disponibile nel sistema. operation=%s",
                operation,
            )
            raise OpenSSLExecutionError(
                "OpenSSL non è installato oppure non è presente nel PATH."
            ) from exc
        except OSError as exc:
            logger.exception(
                "Impossibile avviare OpenSSL. operation=%s",
                operation,
            )
            raise OpenSSLExecutionError(
                f"Impossibile avviare OpenSSL per l'operazione "
                f"'{operation}'."
            ) from exc

        if result.returncode != 0:
            logger.warning(
                "Comando OpenSSL terminato con errore. "
                "operation=%s returncode=%s stderr=%s",
                operation,
                result.returncode,
                result.stderr.strip(),
            )
        else:
            logger.debug(
                "Comando OpenSSL completato. operation=%s",
                operation,
            )

        return result

    @staticmethod
    def _normalize_pdf_extension(payload_path: Path) -> Path:
        """
        Aggiunge l'estensione .pdf quando il contenuto estratto
        comincia con la firma binaria %PDF.

        Returns:
            Il percorso originale oppure il nuovo percorso con
            estensione .pdf.

        Raises:
            SignedContentExtractionError:
                Se il file non può essere letto, rimosso o rinominato.
        """
        try:
            with payload_path.open("rb") as file:
                header = file.read(4)
        except OSError as exc:
            logger.exception(
                "Impossibile leggere il contenuto estratto. path=%s",
                payload_path,
            )
            raise SignedContentExtractionError(
                f"Impossibile leggere il contenuto estratto: "
                f"{payload_path}"
            ) from exc

        if header != b"%PDF" or payload_path.suffix.lower() == ".pdf":
            return payload_path

        pdf_path = payload_path.with_suffix(".pdf")

        try:
            if pdf_path.exists():
                logger.warning(
                    "Il file PDF di destinazione esiste già e sarà "
                    "sostituito. path=%s",
                    pdf_path,
                )
                pdf_path.unlink()

            payload_path.rename(pdf_path)
        except OSError as exc:
            logger.exception(
                "Impossibile rinominare il contenuto come PDF. "
                "source=%s destination=%s",
                payload_path,
                pdf_path,
            )
            raise SignedContentExtractionError(
                f"Impossibile rinominare il contenuto estratto "
                f"come PDF: {payload_path}"
            ) from exc

        logger.info(
            "Contenuto PDF riconosciuto e rinominato. path=%s",
            pdf_path,
        )

        return pdf_path

    @classmethod
    def _read_certificate_info(
        cls,
        cert_pem: Path,
    ) -> tuple[str, bool]:
        """
        Legge il Common Name del certificato e verifica se il
        certificato è temporalmente valido al momento corrente.

        Importante:
            Il booleano restituito indica esclusivamente la validità
            temporale del certificato. Non rappresenta la validazione
            della catena di trust né la validità complessiva della firma.

        Returns:
            Una tupla composta da:
            - nome del firmatario;
            - validità temporale del certificato.
        """
        if not cert_pem.is_file():
            logger.warning(
                "Certificato del firmatario non disponibile. path=%s",
                cert_pem,
            )
            return "Sconosciuto", False

        cert_info = cls._run_openssl(
            [
                "x509",
                "-in",
                str(cert_pem),
                "-noout",
                "-subject",
                "-dates",
            ],
            operation="lettura certificato firmatario",
        )

        if cert_info.returncode != 0:
            logger.error(
                "Impossibile leggere il certificato. path=%s",
                cert_pem,
            )
            return "Sconosciuto", False

        lines = cert_info.stdout.splitlines()
        certificate_text = "\n".join(lines)

        match = re.search(
            r"(?:^|[,/])\s*CN\s*=\s*([^,/]+)",
            certificate_text,
            flags=re.IGNORECASE,
        )

        signer = match.group(1).strip() if match else "Sconosciuto"

        if signer == "Sconosciuto":
            logger.warning(
                "Common Name non trovato nel certificato. path=%s",
                cert_pem,
            )

        date_format = "%b %d %H:%M:%S %Y %Z"

        try:
            start_value = next(
                line
                for line in lines
                if line.startswith("notBefore=")
            ).split("=", 1)[1].strip()

            end_value = next(
                line
                for line in lines
                if line.startswith("notAfter=")
            ).split("=", 1)[1].strip()

            start_date = datetime.strptime(
                start_value,
                date_format,
            ).replace(tzinfo=timezone.utc)

            end_date = datetime.strptime(
                end_value,
                date_format,
            ).replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            temporally_valid = start_date <= now <= end_date

        except (StopIteration, ValueError, IndexError) as exc:
            logger.warning(
                "Impossibile determinare la validità temporale del "
                "certificato. path=%s error=%s",
                cert_pem,
                exc,
            )
            temporally_valid = False

        logger.info(
            "Informazioni certificato lette. signer=%s "
            "temporally_valid=%s",
            signer,
            temporally_valid,
        )

        return signer, temporally_valid

    @classmethod
    def _extract_signed_content_fallback(
        cls,
        p7m_path: Path,
        payload_out: Path,
    ) -> bool:
        """
        Tenta l'estrazione tramite l'interfaccia S/MIME di OpenSSL.

        Il fallback costituisce esclusivamente un percorso alternativo
        di estrazione del contenuto PKCS#7/CMS. Non valida la catena di
        trust, perché viene utilizzata l'opzione -noverify.

        Returns:
            True se il contenuto è stato estratto correttamente,
            False in caso contrario.
        """
        logger.info(
            "Avvio fallback S/MIME. input=%s output=%s",
            p7m_path,
            payload_out,
        )

        fallback = cls._run_openssl(
            [
                "smime",
                "-verify",
                "-inform",
                "DER",
                "-in",
                str(p7m_path),
                "-noverify",
                "-out",
                str(payload_out),
            ],
            operation="estrazione contenuto tramite S/MIME",
        )

        if fallback.returncode != 0:
            logger.error(
                "Fallback S/MIME fallito. input=%s stderr=%s",
                p7m_path,
                fallback.stderr.strip(),
            )
            payload_out.unlink(missing_ok=True)
            return False

        if not payload_out.is_file():
            logger.error(
                "Il fallback S/MIME è terminato senza produrre "
                "il file atteso. output=%s",
                payload_out,
            )
            return False

        logger.info(
            "Fallback S/MIME completato. output=%s",
            payload_out,
        )

        return True

    @classmethod
    def _extract_signer_certificate(
        cls,
        p7m_path: Path,
        cert_pem: Path,
    ) -> bool:
        """
        Estrae i certificati contenuti nella struttura PKCS#7.

        Returns:
            True se il comando ha prodotto il file PEM, altrimenti False.
        """
        result = cls._run_openssl(
            [
                "pkcs7",
                "-inform",
                "DER",
                "-in",
                str(p7m_path),
                "-print_certs",
                "-out",
                str(cert_pem),
            ],
            operation="estrazione certificato PKCS#7",
        )

        if result.returncode != 0 or not cert_pem.is_file():
            logger.warning(
                "Impossibile estrarre il certificato dal file firmato. "
                "input=%s",
                p7m_path,
            )
            cert_pem.unlink(missing_ok=True)
            return False

        return True

    def extract_signed_content(
        self,
        p7m_path: Path,
        out_dir: Path,
    ) -> tuple[Path, str, bool]:
        """
        Estrae il contenuto di un file P7M.

        Il metodo tenta prima l'elaborazione CMS e, in caso di errore,
        utilizza il fallback S/MIME.

        Returns:
            Una tupla composta da:
            - percorsoestratto;
            - Common Name del certificato del firmatario;
            - validità temporale del certificato.

        Raises:
            FileNotFoundError:
                Se il file P7M non esiste.
            ValueError:
                Se il percorso indicato non è un file.
            SignedContentExtractionError:
                Se il contenuto non può essere estratto.
            OpenSSLExecutionError:
                Se OpenSSL non è disponibile.
        """
        p7m_path = Path(p7m_path)
        out_dir = Path(out_dir)

        if not p7m_path.exists():
            raise FileNotFoundError(
                f"File firmato non trovato: {p7m_path}"
            )

        if not p7m_path.is_file():
            raise ValueError(
                f"Il percorso indicato non è un file: {p7m_path}"
            )

        try:
            out_dir.mkdir(
                parents=True,
                exist_ok=True,
            )
        except OSError as exc:
            logger.exception(
                "Impossibile creare la directory di output. path=%s",
                out_dir,
            )
            raise SignedContentExtractionError(
                f"Impossibile creare la directory di output: {out_dir}"
            ) from exc

        base_name = p7m_path.stem
        payload_out = out_dir / base_name
        cert_pem = out_dir / f"{base_name}_cert.pem"

        logger.info(
            "Avvio estrazione contenuto firmato. input=%s output_dir=%s",
            p7m_path,
            out_dir,
        )

        payload_out.unlink(missing_ok=True)
        cert_pem.unlink(missing_ok=True)

        try:
            certificate_extracted = self._extract_signer_certificate(
                p7m_path=p7m_path,
                cert_pem=cert_pem,
            )

            cms_result = self._run_openssl(
                [
                    "cms",
                    "-verify",
                    "-inform",
                    "DER",
                    "-in",
                    str(p7m_path),
                    "-noverify",
                    "-out",
                    str(payload_out),
                ],
                operation="estrazione contenuto tramite CMS",
            )

            if cms_result.returncode != 0:
                logger.warning(
                    "Estrazione CMS fallita; avvio fallback S/MIME. "
                    "input=%s",
                    p7m_path,
                )

                fallback_ok = self._extract_signed_content_fallback(
                    p7m_path=p7m_path,
                    payload_out=payload_out,
                )

                if not fallback_ok:
                    raise SignedContentExtractionError(
                        f"Impossibile estrarre il contenuto firmato "
                        f"da '{p7m_path.name}'."
                    )

            if not payload_out.is_file():
                raise SignedContentExtractionError(
                    "OpenSSL non ha prodotto il contenuto estratto "
                    f"atteso: {payload_out}"
                )

            payload_out = self._normalize_pdf_extension(payload_out)

            if certificate_extracted:
                signer, temporally_valid = self._read_certificate_info(
                    cert_pem
                )
            else:
                signer = "Sconosciuto"
                temporally_valid = False

            logger.info(
                "Estrazione completata. input=%s output=%s signer=%s "
                "certificate_temporally_valid=%s",
                p7m_path,
                payload_out,
                signer,
                temporally_valid,
            )

            return payload_out, signer, temporally_valid

        except (
            OpenSSLExecutionError,
            SignedContentExtractionError,
        ):
            payload_out.unlink(missing_ok=True)
            payload_out.with_suffix(".pdf").unlink(missing_ok=True)

            logger.exception(
                "Estrazione del contenuto firmato non completata. "
                "input=%s",
                p7m_path,
            )
            raise

        finally:
            cert_pem.unlink(missing_ok=True)

    def __call__(self) -> Path:
        """
        Costruisce il trust store PEM a partire dalla TSL.

        Returns:
            Percorso del trust store PEM generato.

        Raises:
            FileNotFoundError:
                Se il file TSL non esiste.
            TrustStoreError:
                Se la TSL non può essere letta o non contiene
                certificati utilizzabili.
        """
        if not self.tsl_path.exists():
            raise FileNotFoundError(
                f"File TSL non trovato: {self.tsl_path}"
            )

        if not self.tsl_path.is_file():
            raise TrustStoreError(
                f"Il percorso TSL non è un file: {self.tsl_path}"
            )

        logger.info(
            "Avvio costruzione trust store. tsl=%s output=%s",
            self.tsl_path,
            self.out_pem,
        )

        try:
            tree = ET.parse(self.tsl_path)
        except ET.ParseError as exc:
            logger.exception(
                "Il file TSL non contiene XML valido. path=%s",
                self.tsl_path,
            )
            raise TrustStoreError(
                f"XML TSL non valido: {self.tsl_path}"
            ) from exc
        except OSError as exc:
            logger.exception(
                "Impossibile leggere il file TSL. path=%s",
                self.tsl_path,
            )
            raise TrustStoreError(
                f"Impossibile leggere il file TSL: {self.tsl_path}"
            ) from exc

        certificates = tree.getroot().findall(
            ".//ds:X509Certificate",
            self.ns,
        )

        if not certificates:
            raise TrustStoreError(
                f"Nessun certificato trovato nella TSL: {self.tsl_path}"
            )

        try:
            self.out_pem.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
        except OSError as exc:
            logger.exception(
                "Impossibile creare la directory del trust store. "
                "path=%s",
                self.out_pem.parent,
            )
            raise TrustStoreError(
                "Impossibile creare la directory di destinazione "
                f"del trust store: {self.out_pem.parent}"
            ) from exc

        written_certificates = 0

        try:
            with self.out_pem.open("wb") as file:
                for certificate in certificates:
                    base64_value = (
                        certificate.text.strip()
                        if certificate.text
                        else ""
                    )

                    if len(base64_value) < 200:
                        logger.debug(
                            "Certificato TSL ignorato perché il "
                            "contenuto è vuoto o troppo corto."
                        )
                        continue

                    file.write(
                        b"-----BEGIN CERTIFICATE-----\n"
                    )

                    for index in range(0, len(base64_value), 64):
                        line = base64_value[index:index + 64]
                        file.write(line.encode("ascii") + b"\n")

                    file.write(
                        b"-----END CERTIFICATE-----\n\n"
                    )

                    written_certificates += 1

        except (OSError, UnicodeEncodeError) as exc:
            self.out_pem.unlink(missing_ok=True)

            logger.exception(
                "Errore durante la scrittura del trust store. path=%s",
                self.out_pem,
            )

            raise TrustStoreError(
                f"Impossibile generare il trust store: {self.out_pem}"
            ) from exc

        if written_certificates == 0:
            self.out_pem.unlink(missing_ok=True)

            raise TrustStoreError(
                f"Nessun certificato utilizzabile trovato nella TSL: "
                f"{self.tsl_path}"
            )

        logger.info(
            "Trust store generato. output=%s certificates=%d",
            self.out_pem,
            written_certificates,
        )

        return self.out_pem

