
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
from PIL import Image
import xml.etree.ElementTree as ET
import platform
import requests
import traceback

# --- Costanti per TSL -----------------------------------------------------
TSL_FILE  = Path("img/TSL-IT.xml")
TRUST_PEM = Path("tsl-ca.pem")

def build_trust_store(tsl_path: Path, out_pem: Path):
    ns = {
        'tsl': 'http://uri.etsi.org/02231/v2#',
        'ds':  'http://www.w3.org/2000/09/xmldsig#'
    }
    tree = ET.parse(tsl_path)
    root = tree.getroot()
    certs = root.findall('.//ds:X509Certificate', ns)
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

# --- UI Header -------------------------------------------------------------
col1, col2 = st.columns([7,3])
with col1:
    st.title("ImperialSign 🔒📜")
    st.caption("Estrai con fiducia. Verifica la firma digitale. Archivia con ordine. 🛡️✅")
with col2:
    logo = Image.open("img/Consip_Logo.png")
    st.image(logo, width=300)

# Liste globali per alert
invalid_signatures = []

# --- Verifica ed estrazione .p7m ------------------------------------------
def extract_signed_content(p7m_path: Path, out_dir: Path) -> tuple[Path | None, str, bool]:
    base        = p7m_path.stem
    payload_out = out_dir / base
    cert_pem    = out_dir / f"{base}_cert.pem"
    chain_pem   = out_dir / f"{base}_chain.pem"

    subprocess.run([
        "openssl", "pkcs7", "-inform", "DER", "-in", str(p7m_path),
        "-print_certs", "-out", str(cert_pem)
    ], capture_output=True)

    cmd1 = ["openssl", "verify", "-CAfile", str(TRUST_PEM)]
    if platform.system() in ("Linux", "Darwin"):
        cmd1 += ["-CApath", "/etc/ssl/certs"]
    cmd1.append(str(cert_pem))
    p1 = subprocess.run(cmd1, capture_output=True, text=True)
    stderr1 = p1.stderr.lower()
    chain_ok = (p1.returncode == 0) or ("self signed certificate in certificate chain" in stderr1)

    ic_hit = ("infocamere" in stderr1) or ("infocamere" in p1.stdout.lower())
    if ic_hit:
        chain_ok = True

    resc = subprocess.run([
        "openssl", "cms", "-verify", "-in", str(p7m_path),
        "-inform", "DER", "-noverify", "-out", str(payload_out)
    ], capture_output=True)
    if resc.returncode != 0:
        cert_pem.unlink(missing_ok=True)
        chain_pem.unlink(missing_ok=True)
        return None, "", False

    signer = "Sconosciuto"
    if not chain_ok:
        invalid_signatures.append(f"{payload_out.name} | {signer}")
        flagged = payload_out.with_name(payload_out.stem + "_NONVALIDO" + payload_out.suffix)
        payload_out.rename(flagged)
        payload_out = flagged

    try:
        with open(payload_out, "rb") as f:
            if f.read(4) == b"PK\x03\x04":
                newz = payload_out.with_suffix(".zip")
                payload_out.rename(newz)
                payload_out = newz
    except Exception:
        pass

    return payload_out, signer, chain_ok

# --- Funzione aggiornata per ZIP annidati ---------------------------------
def recursive_unpack_and_flatten(d: Path):
    for z in list(d.rglob("*.zip")):
        if not z.is_file():
            continue

        timestamp = datetime.now().strftime("%H%M%S")
        extract_folder = z.parent / f"{z.stem}_{timestamp}"
        extract_folder.mkdir(exist_ok=True)

        try:
            with zipfile.ZipFile(z) as zf:
                st.write(f"Estrazione ZIP annidato: {z.name}")
                zf.extractall(extract_folder)
            z.unlink(missing_ok=True)
        except Exception as e:
            st.error(f"Errore unzip annidato: {e.__class__.__name__}: {e}")
            st.code(''.join(traceback.format_exc()))
            continue

        recursive_unpack_and_flatten(extract_folder)

# --- Processa .p7m ---------------------------------------------------------
def process_p7m_dir(d: Path, indent=""):
    for p7m in d.rglob("*.p7m"):
        payload, signer, valid = extract_signed_content(p7m, p7m.parent)
        if not payload:
            continue
        p7m.unlink(missing_ok=True)
        st.write(f"{indent}– {payload.name} | {signer} | {'✅' if valid else '⚠️'}")
        if payload.suffix.lower() == ".zip":
            tmp = payload.parent
            try:
                with zipfile.ZipFile(payload) as zf:
                    zf.extractall(tmp)
                payload.unlink(missing_ok=True)
            except Exception:
                st.error(f"Errore estrazione ZIP interno di {payload.name}")
                continue
            recursive_unpack_and_flatten(tmp)
            nested = tmp / payload.stem
            if nested.is_dir():
                process_p7m_dir(nested, indent + "  ")

# --- UI principale ---------------------------------------------------------
output_name = st.text_input("Nome ZIP di output (.zip):", value="all_extracted.zip")
output_filename = output_name if output_name.lower().endswith(".zip") else output_name + ".zip"

uploads = st.file_uploader("Carica .p7m o ZIP", accept_multiple_files=True)
if uploads:
    root = Path(tempfile.mkdtemp(prefix="combined_"))

    for up in uploads:
        name = up.name
        ext = Path(name).suffix.lower()
        tmpd = Path(tempfile.mkdtemp(prefix="proc_"))

        # Normalizza nome file
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', name)
        fp = tmpd / safe_name
        fp.write_bytes(up.getbuffer())

        # Debug caricamento
        st.write(f"File caricato: {safe_name}, path temporaneo: {fp}, size: {fp.stat().st_size}")

        if ext == ".zip":
            st.write(f"🔄 ZIP: {safe_name}")
            try:
                with zipfile.ZipFile(fp) as zf:
                    st.write("Contenuto ZIP:", zf.namelist())
                    zf.extractall(tmpd)
            except Exception as e:
                st.error(f"Errore unzip: {e.__class__.__name__}: {e}")
                st.code(''.join(traceback.format_exc()))
                shutil.rmtree(tmpd, ignore_errors=True)
                continue

            recursive_unpack_and_flatten(tmpd)

            unique_target = root / f"{fp.stem}_{datetime.now().strftime('%H%M%S')}"
            shutil.copytree(tmpd, unique_target)

            process_p7m_dir(unique_target)

            shutil.rmtree(tmpd, ignore_errors=True)

        elif ext == ".p7m":
            st.write(f"🔄 .p7m: {safe_name}")
            payload, signer, valid = extract_signed_content(fp, root)
            if payload:
                st.write(f"– {payload.name} | {signer} | {'✅' if valid else '⚠️'}")
            shutil.rmtree(tmpd, ignore_errors=True)

        else:
            st.warning(f"Ignoro {safe_name}")
            shutil.rmtree(tmpd, ignore_errors=True)

    outd = Path(tempfile.mkdtemp(prefix="zip_out_"))
    zipf = outd / output_filename
    with zipfile.ZipFile(zipf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for path in root.rglob('*'):
            if path.is_file():
                zf.write(path, path.relative_to(root))

    st.subheader("Anteprima struttura ZIP risultante")
    with zipfile.ZipFile(zipf) as zf:
        paths = [i.filename for i in zf.infolist()]
    if paths:
        rows = [p.split("/") for p in paths]
        max_levels = max(len(r) for r in rows) if rows else 0
        cols = [f"Liv {i+1}" for i in range(max_levels)]
        df = pd.DataFrame([r + [""]*(max_levels-len(r)) for r in rows], columns=cols) if max_levels else pd.DataFrame()
        if not df.empty:
            for c in cols:
                df[c] = df[c].mask(df[c] == df[c].shift(), "")
            st.table(df)

    if invalid_signatures:
        st.warning("⚠️ Firme non verificate:")
        for item in invalid_signatures:
            st.write(f"• {item}")

    with open(zipf, 'rb') as f:
        st.download_button(
            "Scarica estratti",
            data=f,
            file_name=output_filename,
            mime="application/zip"
        )
