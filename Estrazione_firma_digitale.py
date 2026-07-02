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
        'tsl': 'http://uri.etsi.org/02231/v2#',
        'ds': 'http://www.w3.org/2000/09/xmldsig#'
    }

    tree = ET.parse(tsl_path)
    certs = tree.getroot().findall('.//ds:X509Certificate', ns)

    if not certs:
        raise RuntimeError(f"Nessun certificato trovato in {tsl_path}")

    with open(out_pem, 'wb') as f:
        for cert in certs:
            b64 = cert.text.strip() if cert.text else ""
            if len(b64) < 200:
                continue

            f.write(b"-----BEGIN CERTIFICATE-----\n")
            for i in range(0, len(b64), 64):
                f.write(b64[i:i+64].encode('ascii') + b"\n")
            f.write(b"-----END CERTIFICATE-----\n\n")

try:
    build_trust_store(TSL_FILE, TRUST_PEM)
except Exception as e:
    st.error(f"Impossibile costruire il trust store: {e}")
    st.stop()

# --- HEADER --------------------------------------------------------------
st.title("ImperialSign 🔒📜")
st.caption("Estrai con fiducia. Verifica la firma digitale. Archivia con ordine. 🛡️✅")


# --- Estrazione p7m ------------------------------------------------------
def extract_signed_content(p7m_path: Path, out_dir: Path) -> tuple[Path | None, str, bool]:
    base = p7m_path.stem
    payload_out = out_dir / base
    cert_pem = out_dir / f"{base}_cert.pem"

    subprocess.run([
        "openssl", "pkcs7", "-inform", "DER", "-in", str(p7m_path),
        "-print_certs", "-out", str(cert_pem)
    ], capture_output=True)

    proc = subprocess.run([
        "openssl", "cms", "-verify", "-in", str(p7m_path),
        "-inform", "DER", "-noverify", "-out", str(payload_out)
    ], capture_output=True, text=True)

    if proc.returncode != 0:
        err = proc.stderr.lower()

        if "bad signature" in err:
            st.warning(f"{p7m_path.name}: firma non valida. Estraggo contenuto.")

            fallback = subprocess.run([
                "openssl", "smime", "-verify", "-inform", "DER",
                "-in", str(p7m_path), "-noverify", "-out", str(payload_out)
            ], capture_output=True, text=True)

            if fallback.returncode != 0:
                st.error(f"Estrazione fallback fallita: {fallback.stderr.strip()}")
                cert_pem.unlink(missing_ok=True)
                return None, "", False
        else:
            st.error(f"Errore estrazione '{p7m_path.name}': {proc.stderr.strip()}")
            cert_pem.unlink(missing_ok=True)
            return None, "", False

    # Detect PDF
    try:
        with open(payload_out, 'rb') as f:
            if f.read(4) == b'%PDF':
                new_pdf = payload_out.with_suffix('.pdf')
                payload_out.rename(new_pdf)
                payload_out = new_pdf
    except Exception:
        pass

    # Cert info
    cert_info = subprocess.run([
        "openssl", "x509", "-in", str(cert_pem),
        "-noout", "-subject", "-dates"
    ], capture_output=True, text=True)

    cert_pem.unlink(missing_ok=True)

    if cert_info.returncode != 0:
        return payload_out, "Sconosciuto", False

    lines = cert_info.stdout.splitlines()
    subj = "\n".join(lines)

    m = re.search(r"CN\s*=\s*([^,\/]+)", subj)
    signer = m.group(1).strip() if m else "Sconosciuto"

    fmt = "%b %d %H:%M:%S %Y %Z"

    try:
        start = next(l for l in lines if 'notBefore' in l).split('=',1)[1].strip()
        end = next(l for l in lines if 'notAfter' in l).split('=',1)[1].strip()

        valid = datetime.strptime(start, fmt) <= datetime.utcnow() <= datetime.strptime(end, fmt)
    except Exception:
        valid = False

    return payload_out, signer, valid


# --- ZIP annidati --------------------------------------------------------
def recursive_unpack_and_flatten(d: Path):
    for z in d.rglob("*.zip"):
        if not z.is_file():
            continue

        dst = z.parent / f"{z.stem}_unz"
        shutil.rmtree(dst, ignore_errors=True)
        dst.mkdir()

        try:
            with zipfile.ZipFile(z) as zf:
                zf.extractall(dst)
        except Exception:
            z.unlink(missing_ok=True)
            continue

        z.unlink(missing_ok=True)

        children = list(dst.iterdir())
        if len(children) == 1 and children[0].is_dir():
            for c in children[0].iterdir():
                shutil.move(str(c), dst)
            children[0].rmdir()

        recursive_unpack_and_flatten(dst)


# --- Process directory ---------------------------------------------------
def process_p7m_dir(d: Path, indent=""):
    for p7m in d.rglob("*.p7m"):
        payload, signer, valid = extract_signed_content(p7m, p7m.parent)

        if not payload:
            continue

        p7m.unlink(missing_ok=True)

        st.write(f"{indent}– {payload.name} | {signer} | {'✅' if valid else '⚠️'}")

        if payload.suffix.lower() == ".zip":
            try:
                with zipfile.ZipFile(payload) as zf:
                    zf.extractall(payload.parent)
                recursive_unpack_and_flatten(payload.parent)
            except Exception:
                st.error(f"Errore estrazione ZIP interno di {payload.name}")

            process_p7m_dir(payload.parent, indent + "  ")


# --- UI principale -------------------------------------------------------
output_name = st.text_input("Nome ZIP di output (.zip):", value="all_extracted.zip")
output_filename = output_name if output_name.lower().endswith(".zip") else output_name + ".zip"

uploads = st.file_uploader("Carica .p7m o ZIP", accept_multiple_files=True)

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
                st.error(f"Errore unzip: {e}")

            finally:
                shutil.rmtree(tmpd, ignore_errors=True)

        elif ext == ".p7m":
            st.write(f"🔄 .p7m: {name}")

            payload, signer, valid = extract_signed_content(fp, root)

            if payload:
                st.write(f"– {payload.name} | {signer} | {'✅' if valid else '⚠️'}")

            shutil.rmtree(tmpd, ignore_errors=True)

        else:
            st.warning(f"Ignoro {name}")

    # Pulizia
    for d in root.rglob("*_unz"):
        shutil.rmtree(d, ignore_errors=True)

    for p in root.rglob("*.p7m"):
        p.unlink(missing_ok=True)

    # --- ZIP FINALE + ANTEPRIMA ------------------------------------------
    outd = Path(tempfile.mkdtemp(prefix="zip_out_"))
    zipf = outd / output_filename

    with zipfile.ZipFile(zipf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for path in root.iterdir():
            if path.is_dir():
                for file in path.rglob('*'):
                    if file.is_file() and '_unz' not in file.parts and file.suffix.lower() != '.p7m':
                        zf.write(file, file.relative_to(root))
            else:
                if path.suffix.lower() != '.p7m':
                    zf.write(path, path.name)

    st.subheader("Anteprima struttura ZIP risultante")

    with zipfile.ZipFile(zipf) as zf:
        paths = [i.filename for i in zf.infolist()
                 if '_unz' not in i.filename and not i.filename.lower().endswith('.p7m')]

    if paths:
        rows = [p.split("/") for p in paths]
        max_levels = max(len(r) for r in rows)
        cols = [f"Liv {i+1}" for i in range(max_levels)]

        df = pd.DataFrame(
            [r + [""]*(max_levels-len(r)) for r in rows],
            columns=cols
        )

        for c in cols:
            df[c] = df[c].mask(df[c] == df[c].shift(), "")

        st.table(df)

    with open(zipf, 'rb') as f:
        st.download_button(
            "Scarica estratti",
            data=f,
            file_name=output_filename,
            mime="application/zip"
        )
