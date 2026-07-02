import streamlit as st
import os
import zipfile
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import re
import pandas as pd
import xml.etree.ElementTree as ET


# --- Costanti per TSL -----------------------------------------------------
TSL_FILE = Path("img/TSL-IT.xml")
TRUST_PEM = Path("tsl-ca.pem")


def build_trust_store(tsl_path: Path, out_pem: Path):
    ns = {
        "tsl": "http://uri.etsi.org/02231/v2#",
        "ds": "http://www.w3.org/2000/09/xmldsig#"
    }

    tree = ET.parse(tsl_path)
    certs = tree.getroot().findall(".//ds:X509Certificate", ns)

    if not certs:
        raise RuntimeError(f"Nessun certificato trovato in {tsl_path}")

    with open(out_pem, "wb") as f:
        for cert in certs:
            b64 = cert.text.strip() if cert.text else ""

            if len(b64) < 200:
                continue

            f.write(b"-----BEGIN CERTIFICATE-----\n")

            for i in range(0, len(b64), 64):
                f.write(b64[i:i + 64].encode("ascii") + b"\n")

            f.write(b"-----END CERTIFICATE-----\n\n")


try:
    build_trust_store(TSL_FILE, TRUST_PEM)
except Exception as e:
    st.error(f"Impossibile costruire il trust store: {e}")
    st.stop()


# --- HEADER --------------------------------------------------------------
st.title("ImperialSign 🔒📜")
st.caption("Estrai con fiducia. Verifica la firma digitale. Archivia con ordine. 🛡️✅")


# --- Estrazione singolo livello p7m --------------------------------------
def extract_signed_content(p7m_path: Path, out_dir: Path) -> tuple[Path | None, str, bool]:
    """
    Estrae un singolo livello di firma da un file .p7m.

    Esempio:
    - file.pdf.p7m      -> file.pdf
    - file.pdf.p7m.p7m  -> file.pdf.p7m

    Se il risultato è ancora .p7m, sarà gestito dalla funzione unwrap_p7m_file().
    """

    base = p7m_path.stem
    payload_out = out_dir / base
    cert_pem = out_dir / f"{base}_cert.pem"

    # Estrazione certificato firmatario
    subprocess.run(
        [
            "openssl",
            "pkcs7",
            "-inform",
            "DER",
            "-in",
            str(p7m_path),
            "-print_certs",
            "-out",
            str(cert_pem)
        ],
        capture_output=True,
        text=True
    )

    # Verifica ed estrazione contenuto
    proc = subprocess.run(
        [
            "openssl",
            "cms",
            "-verify",
            "-in",
            str(p7m_path),
            "-inform",
            "DER",
            "-noverify",
            "-out",
            str(payload_out)
        ],
        capture_output=True,
        text=True
    )

    if proc.returncode != 0:
        err = proc.stderr.lower()

        if "bad signature" in err:
            st.warning(f"{p7m_path.name}: firma non valida. Provo comunque a estrarre il contenuto.")

            fallback = subprocess.run(
                [
                    "openssl",
                    "smime",
                    "-verify",
                    "-inform",
                    "DER",
                    "-in",
                    str(p7m_path),
                    "-noverify",
                    "-out",
                    str(payload_out)
                ],
                capture_output=True,
                text=True
            )

            if fallback.returncode != 0:
                st.error(f"Estrazione fallback fallita per {p7m_path.name}: {fallback.stderr.strip()}")
                cert_pem.unlink(missing_ok=True)
                return None, "", False

        else:
            st.error(f"Errore estrazione '{p7m_path.name}': {proc.stderr.strip()}")
            cert_pem.unlink(missing_ok=True)
            return None, "", False

    # Se il contenuto estratto è un PDF ma non ha estensione .pdf, rinomino
    try:
        with open(payload_out, "rb") as f:
            header = f.read(4)

        if header == b"%PDF" and payload_out.suffix.lower() != ".pdf":
            new_pdf = payload_out.with_suffix(".pdf")

            if new_pdf.exists():
                new_pdf.unlink()

            payload_out.rename(new_pdf)
            payload_out = new_pdf

    except Exception:
        pass

    # Lettura info certificato
    cert_info = subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(cert_pem),
            "-noout",
            "-subject",
            "-dates"
        ],
        capture_output=True,
        text=True
    )

    cert_pem.unlink(missing_ok=True)

    if cert_info.returncode != 0:
        return payload_out, "Sconosciuto", False

    lines = cert_info.stdout.splitlines()
    subj = "\n".join(lines)

    m = re.search(r"CN\s*=\s*([^,/]+)", subj)
    signer = m.group(1).strip() if m else "Sconosciuto"

    fmt = "%b %d %H:%M:%S %Y %Z"

    try:
        start = next(l for l in lines if "notBefore" in l).split("=", 1)[1].strip()
        end = next(l for l in lines if "notAfter" in l).split("=", 1)[1].strip()

        valid = datetime.strptime(start, fmt) <= datetime.utcnow() <= datetime.strptime(end, fmt)

    except Exception:
        valid = False

    return payload_out, signer, valid


# --- Estrazione multilivello p7m -----------------------------------------
def unwrap_p7m_file(p7m_path: Path, out_dir: Path, indent: str = "") -> tuple[Path | None, list[dict]]:
    """
    Estrae ricorsivamente un file .p7m finché il risultato non è più un .p7m.

    Gestisce correttamente casi come:
    - documento.pdf.p7m
    - documento.pdf.p7m.p7m
    - documento.xml.p7m.p7m
    - archivio.zip.p7m.p7m

    Restituisce:
    - path finale estratto
    - lista livelli firma
    """

    current = p7m_path
    levels = []
    level = 1

    while current and current.suffix.lower() == ".p7m":
        payload, signer, valid = extract_signed_content(current, out_dir)

        if not payload:
            return None, levels

        levels.append(
            {
                "level": level,
                "source": current.name,
                "payload": payload.name,
                "signer": signer,
                "valid": valid
            }
        )

        st.write(
            f"{indent}– Livello firma {level}: {current.name} → {payload.name} | "
            f"{signer} | {'✅' if valid else '⚠️'}"
        )

        # Rimuovo il contenitore .p7m appena lavorato.
        # Non rimuovo il payload se è ancora .p7m perché deve essere processato al giro successivo.
        try:
            if current.exists() and current != payload:
                current.unlink(missing_ok=True)
        except Exception:
            pass

        current = payload
        level += 1

    return current, levels


# --- ZIP annidati --------------------------------------------------------
def recursive_unpack_and_flatten(d: Path):
    """
    Estrae tutti gli ZIP annidati presenti dentro la directory.
    Se lo ZIP contiene una sola cartella wrapper, la appiattisce.
    """

    zip_files = list(d.rglob("*.zip"))

    for z in zip_files:
        if not z.is_file():
            continue

        dst = z.parent / f"{z.stem}_unz"
        shutil.rmtree(dst, ignore_errors=True)
        dst.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(z) as zf:
                zf.extractall(dst)

        except Exception:
            z.unlink(missing_ok=True)
            continue

        z.unlink(missing_ok=True)

        children = list(dst.iterdir())

        if len(children) == 1 and children[0].is_dir():
            wrapper = children[0]

            for c in wrapper.iterdir():
                shutil.move(str(c), dst)

            wrapper.rmdir()

        recursive_unpack_and_flatten(dst)


# --- Process directory ---------------------------------------------------
def process_p7m_dir(d: Path, indent: str = ""):
    """
    Processa tutti i .p7m dentro una directory, compresi:
    - p7m semplici
    - p7m multilivello
    - p7m che producono ZIP
    - ZIP interni che contengono altri p7m
    """

    while True:
        p7m_files = list(d.rglob("*.p7m"))

        if not p7m_files:
            break

        processed_any = False

        for p7m in p7m_files:
            if not p7m.exists():
                continue

            final_payload, levels = unwrap_p7m_file(p7m, p7m.parent, indent)

            if not final_payload:
                continue

            processed_any = True

            # Se il risultato finale è uno ZIP, lo estraggo e poi cerco eventuali altri p7m
            if final_payload.suffix.lower() == ".zip":
                try:
                    st.write(f"{indent}📦 Estraggo ZIP interno: {final_payload.name}")

                    with zipfile.ZipFile(final_payload) as zf:
                        zf.extractall(final_payload.parent)

                    final_payload.unlink(missing_ok=True)

                    recursive_unpack_and_flatten(final_payload.parent)

                except Exception as e:
                    st.error(f"Errore estrazione ZIP interno di {final_payload.name}: {e}")

        if not processed_any:
            break


# --- UI principale -------------------------------------------------------
output_name = st.text_input("Nome ZIP di output (.zip):", value="all_extracted.zip")
output_filename = output_name if output_name.lower().endswith(".zip") else output_name + ".zip"

uploads = st.file_uploader(
    "Carica .p7m o ZIP",
    accept_multiple_files=True,
    type=["p7m", "zip"]
)

if uploads:
    root = Path(tempfile.mkdtemp(prefix="combined_"))

    for up in uploads:
        name = up.name
        ext = Path(name).suffix.lower()

        tmpd = Path(tempfile.mkdtemp(prefix="proc_"))
        fp = tmpd / name
        fp.write_bytes(up.getbuffer())

        if ext == ".zip":
            st.write(f"🔄 ZIP: {name}")

            try:
                with zipfile.ZipFile(fp) as zf:
                    zf.extractall(tmpd)

                recursive_unpack_and_flatten(tmpd)

                target = root / fp.stem
                shutil.rmtree(target, ignore_errors=True)
                shutil.copytree(tmpd, target)

                process_p7m_dir(target)

            except Exception as e:
                st.error(f"Errore unzip di {name}: {e}")

            finally:
                shutil.rmtree(tmpd, ignore_errors=True)

        elif ext == ".p7m":
            st.write(f"🔄 .p7m: {name}")

            final_payload, levels = unwrap_p7m_file(fp, root)

            if final_payload:
                # Se il risultato finale è uno ZIP, lo estraggo dentro root
                if final_payload.suffix.lower() == ".zip":
                    try:
                        st.write(f"📦 Estraggo ZIP finale: {final_payload.name}")

                        with zipfile.ZipFile(final_payload) as zf:
                            zf.extractall(root)

                        final_payload.unlink(missing_ok=True)

                        recursive_unpack_and_flatten(root)
                        process_p7m_dir(root)

                    except Exception as e:
                        st.error(f"Errore estrazione ZIP finale di {final_payload.name}: {e}")

                else:
                    st.write(f"✅ Estratto finale: {final_payload.name}")

            shutil.rmtree(tmpd, ignore_errors=True)

        else:
            st.warning(f"Ignoro {name}")
            shutil.rmtree(tmpd, ignore_errors=True)

    # Pulizia cartelle temporanee generate per ZIP annidati
    for d in list(root.rglob("*_unz")):
        shutil.rmtree(d, ignore_errors=True)

    # Pulizia eventuali p7m residui
    for p in list(root.rglob("*.p7m")):
        p.unlink(missing_ok=True)

    # --- ZIP FINALE + ANTEPRIMA ------------------------------------------
    outd = Path(tempfile.mkdtemp(prefix="zip_out_"))
    zipf = outd / output_filename

    with zipfile.ZipFile(zipf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in root.iterdir():
            if path.is_dir():
                for file in path.rglob("*"):
                    if (
                        file.is_file()
                        and "_unz" not in file.parts
                        and file.suffix.lower() != ".p7m"
                    ):
                        zf.write(file, file.relative_to(root))
            else:
                if path.suffix.lower() != ".p7m":
                    zf.write(path, path.name)

    st.subheader("Anteprima struttura ZIP risultante")

    with zipfile.ZipFile(zipf) as zf:
        paths = [
            i.filename
            for i in zf.infolist()
            if "_unz" not in i.filename and not i.filename.lower().endswith(".p7m")
        ]

    if paths:
        rows = [p.split("/") for p in paths]
        max_levels = max(len(r) for r in rows)
        cols = [f"Liv {i + 1}" for i in range(max_levels)]

        df = pd.DataFrame(
            [r + [""] * (max_levels - len(r)) for r in rows],
            columns=cols
        )

        for c in cols:
            df[c] = df[c].mask(df[c] == df[c].shift(), "")

        st.table(df)

    else:
        st.info("Nessun file estratto da mostrare nell'anteprima.")

    with open(zipf, "rb") as f:
        st.download_button(
            "Scarica estratti",
            data=f,
            file_name=output_filename,
            mime="application/zip"
        )
