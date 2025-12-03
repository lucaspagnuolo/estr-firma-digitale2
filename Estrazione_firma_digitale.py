
import streamlit as st
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
import hashlib
import traceback
import os

# --- Costanti per TSL -----------------------------------------------------
TSL_FILE = Path("img/TSL-IT.xml")
TRUST_PEM = Path("tsl-ca.pem")

def build_trust_store(tsl_path: Path, out_pem: Path):
    ns = {'tsl': 'http://uri.etsi.org/02231/v2#', 'ds': 'http://www.w3.org/2000/09/xmldsig#'}
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
col1, col2 = st.columns([7, 3])
with col1:
    st.title("ImperialSign 🔒📜")
    st.caption("Estrai ZIP annidati, verifica firme .p7m, deduplica e conserva i nomi originali. 🛡️✅")
with col2:
    try:
        logo = Image.open("img/Consip_Logo.png")
        st.image(logo, width=300)
    except Exception:
        pass

# --- Preferenze utente -----------------------------------------------------
RENAME_NONVALID = st.checkbox("Aggiungi suffisso _NONVALIDO ai file con firma non verificata (.p7m)", value=False)
CONFLICT_STRATEGY = st.selectbox(
    "Gestione file con stesso nome ma contenuti diversi",
    ["Rinomina con suffisso _conflict_<timestamp>", "Sposta in sottocartella _conflicts"],
    index=0
)

invalid_signatures = []
conflict_logs = []

# --- Utility ---------------------------------------------------------------
def file_hash(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            h.update(chunk)
    return h.hexdigest()

def files_equal(a: Path, b: Path) -> bool:
    try:
        if a.stat().st_size != b.stat().st_size:
            return False
        return file_hash(a) == file_hash(b)
    except Exception:
        return False

def unique_collision_name(target: Path, suffix_base: str = "_conflict") -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    return target.with_name(f"{target.stem}{suffix_base}_{ts}{target.suffix}")

def ensure_conflicts_dir(dst: Path) -> Path:
    cdir = dst / "_conflicts"
    cdir.mkdir(exist_ok=True)
    return cdir

def is_zip_file(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            return f.read(4) == b"PK\x03\x04"
    except Exception:
        return False

def is_pdf_file(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            return f.read(4) == b"%PDF"
    except Exception:
        return False

def _merge_move_with_dedup(src: Path, dst: Path):
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            target.mkdir(exist_ok=True)
            _merge_move_with_dedup(item, target)
            shutil.rmtree(item, ignore_errors=True)
        else:
            if target.exists():
                if files_equal(item, target):
                    item.unlink(missing_ok=True)
                else:
                    if CONFLICT_STRATEGY.startswith("Rinomina"):
                        new_target = unique_collision_name(target)
                        conflict_logs.append(f"Conflitto: {target} vs nuovo -> rinominato {new_target.name}")
                        shutil.move(str(item), str(new_target))
                    else:
                        cdir = ensure_conflicts_dir(dst)
                        new_target = cdir / item.name
                        if new_target.exists():
                            new_target = unique_collision_name(new_target)
                        conflict_logs.append(f"Conflitto: {target} vs nuovo -> spostato in {new_target}")
                        shutil.move(str(item), str(new_target))
            else:
                shutil.move(str(item), str(target))
    shutil.rmtree(src, ignore_errors=True)

def collapse_single_wrappers(root: Path):
    changed = True
    while changed:
        changed = False
        for d in list(root.rglob("*")):
            if d.is_dir():
                children = list(d.iterdir())
                if len(children) == 1 and children[0].is_dir():
                    inner = children[0]
                    for c in inner.iterdir():
                        shutil.move(str(c), str(d / c.name))
                    shutil.rmtree(inner, ignore_errors=True)
                    changed = True

# --- Verifica ed estrazione .p7m con approccio misto ----------------------
def extract_signed_content(p7m_path: Path, out_dir: Path, rename_nonvalid: bool) -> tuple[Path | None, str, bool]:
    base = p7m_path.stem
    payload_out = out_dir / base
    cert_pem = out_dir / f"{base}_cert.pem"
    chain_pem = out_dir / f"{base}_chain.pem"

    subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-in", str(p7m_path),
                    "-print_certs", "-out", str(cert_pem)], capture_output=True)

    cmd1 = ["openssl", "verify", "-CAfile", str(TRUST_PEM)]
    if platform.system() in ("Linux", "Darwin"):
        cmd1 += ["-CApath", "/etc/ssl/certs"]
    cmd1.append(str(cert_pem))
    p1 = subprocess.run(cmd1, capture_output=True, text=True)
    chain_ok = (p1.returncode == 0) or ("self signed certificate" in p1.stderr.lower())

    resc = subprocess.run(["openssl", "cms", "-verify", "-in", str(p7m_path),
                           "-inform", "DER", "-noverify", "-out", str(payload_out)], capture_output=True)
    if resc.returncode != 0:
        return None, "", False

    # Approccio misto: magic number + fallback nome
    try:
        name_lower = p7m_path.name.lower()

        # ✅ Priorità assoluta a .pdf.p7m
        if ".pdf.p7m" in name_lower:
            newpdf = payload_out.with_suffix(".pdf")
            if payload_out.exists():
                payload_out.rename(newpdf)
            payload_out = newpdf
        elif is_zip_file(payload_out):
            if ".docx.p7m" in name_lower:
                newdocx = payload_out.with_suffix(".docx")
                payload_out.rename(newdocx)
                payload_out = newdocx
            else:
                newz = payload_out.with_suffix(".zip")
                if newz.name.endswith(".zip.zip"):
                    newz = Path(newz.as_posix().replace(".zip.zip", ".zip"))
                payload_out.rename(newz)
                payload_out = newz
        elif is_pdf_file(payload_out):
            newpdf = payload_out.with_suffix(".pdf")
            payload_out.rename(newpdf)
            payload_out = newpdf
        elif ".docx.p7m" in name_lower:
            newdocx = payload_out.with_suffix(".docx")
            payload_out.rename(newdocx)
            payload_out = newdocx
        elif ".doc.p7m" in name_lower:
            newdoc = payload_out.with_suffix(".doc")
            payload_out.rename(newdoc)
            payload_out = newdoc
    except Exception:
        pass

    signer = "Sconosciuto"
    res2 = subprocess.run(["openssl", "x509", "-in", str(cert_pem),
                           "-noout", "-subject"], capture_output=True, text=True)
    if res2.returncode == 0:
        m = re.search(r"(?:CN|SN|UID|emailAddress|SERIALNUMBER)\s*=\s*([^,\/]+)", res2.stdout)
        signer = m.group(1).strip() if m else "Sconosciuto"

    cert_pem.unlink(missing_ok=True)
    chain_pem.unlink(missing_ok=True)

    if not chain_ok:
        invalid_signatures.append(f"{payload_out.name} | {signer}")
        if rename_nonvalid:
            flagged = payload_out.with_name(payload_out.stem + "_NONVALIDO" + payload_out.suffix)
            if flagged.exists():
                flagged = unique_collision_name(flagged)
            try:
                payload_out.rename(flagged)
                payload_out = flagged
            except Exception:
                pass

    return payload_out, signer, chain_ok

# --- Estrazione ZIP annidati -----------------------------------------------
def recursive_extract_flat_into(target_dir: Path):
    while True:
        zips = [z for z in target_dir.rglob("*.zip") if z.is_file()]
        if not zips:
            break
        for z in zips:
            if not is_zip_file(z):
                continue
            tmp_extract = Path(tempfile.mkdtemp(prefix="unz_"))
            try:
                with zipfile.ZipFile(z) as zf:
                    zf.extractall(tmp_extract)
            except Exception:
                continue
            _merge_move_with_dedup(tmp_extract, z.parent)
            z.unlink(missing_ok=True)
    collapse_single_wrappers(target_dir)

# --- Processa .p7m ---------------------------------------------------------
def process_p7m_dir(d: Path):
    for p7m in d.rglob("*.p7m"):
        payload, signer, valid = extract_signed_content(p7m, p7m.parent, RENAME_NONVALID)
        if not payload or not payload.exists():
            st.write(f"⚠️ Non estratto: {p7m.name} (mantengo il file originale)")
            continue
        p7m.unlink(missing_ok=True)  # ✅ Elimina solo se estratto
        st.write(f"✅ Estratto: {payload.name} | {signer} | {'Valido' if valid else 'Non valido'}")
        if is_zip_file(payload):
            tmp_extract = Path(tempfile.mkdtemp(prefix="unz_p7m_"))
            with zipfile.ZipFile(payload) as zf:
                zf.extractall(tmp_extract)
            _merge_move_with_dedup(tmp_extract, payload.parent)
            payload.unlink(missing_ok=True)
            recursive_extract_flat_into(payload.parent)

# --- UI principale ---------------------------------------------------------
output_name = st.text_input("Nome ZIP di output (.zip):", value="all_extracted.zip")
output_filename = output_name if output_name.lower().endswith(".zip") else output_name + ".zip"

uploads = st.file_uploader("Carica .p7m o ZIP", accept_multiple_files=True)
if uploads:
    root = Path(tempfile.mkdtemp(prefix="combined_"))
    for up in uploads:
        original_name = up.name
        ext = Path(original_name).suffix.lower()
        tmpd = Path(tempfile.mkdtemp(prefix="proc_"))
        fp = tmpd / re.sub(r'[^a-zA-Z0-9_.-]', '_', original_name)
        fp.write_bytes(up.getbuffer())

        if ext == ".zip":
            dest = root / Path(original_name).stem
            dest.mkdir(parents=True, exist_ok=True)
            tmp_extract = Path(tempfile.mkdtemp(prefix="unz_top_"))
            with zipfile.ZipFile(fp) as zf:
                zf.extractall(tmp_extract)
            _merge_move_with_dedup(tmp_extract, dest)
            recursive_extract_flat_into(dest)
            process_p7m_dir(dest)
        elif ext == ".p7m":
            payload, signer, valid = extract_signed_content(fp, root, RENAME_NONVALID)
            if payload and payload.exists():
                st.write(f"✅ Estratto: {payload.name} | {signer} | {'Valido' if valid else 'Non valido'}")
                if is_zip_file(payload):
                    tmp_extract = Path(tempfile.mkdtemp(prefix="unz_p7m_top_"))
                    with zipfile.ZipFile(payload) as zf:
                        zf.extractall(tmp_extract)
                    _merge_move_with_dedup(tmp_extract, root)
                    recursive_extract_flat_into(root)
                fp.unlink(missing_ok=True)
            else:
                st.write(f"⚠️ Non estratto: {fp.name} (mantengo il file originale)")
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
        max_levels = max(len(r) for r in rows)
        cols = [f"Liv {i+1}" for i in range(max_levels)]
        df = pd.DataFrame([r + [""]*(max_levels-len(r)) for r in rows], columns=cols)
        for c in cols:
            df[c] = df[c].mask(df[c] == df[c].shift(), "")
        st.table(df)

    if invalid_signatures:
        st.warning("⚠️ Firme non verificate:")
        for item in invalid_signatures:
            st.write(f"• {item}")

    if conflict_logs:
        st.info("ℹ️ Conflitti gestiti:")
        for msg in conflict_logs:
            st.write(f"• {msg}")

    with open(zipf, 'rb') as f:
        st.download_button("Scarica estratti", data=f, file_name=output_filename, mime="application/zip")
