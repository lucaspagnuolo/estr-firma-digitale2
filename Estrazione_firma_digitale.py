
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
import requests
import hashlib
import traceback
import os

# --- Costanti per TSL -----------------------------------------------------
TSL_FILE  = Path("img/TSL-IT.xml")
TRUST_PEM = Path("tsl-ca.pem")

def build_trust_store(tsl_path: Path, out_pem: Path):
    ns = { 'tsl': 'http://uri.etsi.org/02231/v2#', 'ds':  'http://www.w3.org/2000/09/xmldsig#' }
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

# Costruzione trust store
try:
    build_trust_store(TSL_FILE, TRUST_PEM)
except Exception as e:
    st.error(f"Impossibile costruire il trust store: {e}")
    st.stop()

# --- UI Header -------------------------------------------------------------
col1, col2 = st.columns([7,3])
with col1:
    st.title("ImperialSign 🔒📜")
    st.caption("Estrai ZIP annidati, verifica firme .p7m, e deduplica/flatten dei contenuti. 🛡️✅")
with col2:
    try:
        logo = Image.open("img/Consip_Logo.png")
        st.image(logo, width=300)
    except Exception:
        pass

# Liste globali per alert
invalid_signatures = []
duplication_alerts = []  # opzionale, puoi non usarla in questa versione

# --- Utilità di file -------------------------------------------------------
def file_hash(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """SHA256 del file per confronti contenuto-identici."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            h.update(chunk)
    return h.hexdigest()

def files_equal(a: Path, b: Path) -> bool:
    """Confronto rapido: size + (se uguali) hash."""
    try:
        if a.stat().st_size != b.stat().st_size:
            return False
        return file_hash(a) == file_hash(b)
    except Exception:
        return False

def unique_collision_name(target: Path, suffix_base: str = "_conflict") -> Path:
    """Genera un nome univoco affiancando un suffisso con timestamp."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    if target.suffix:
        return target.with_name(f"{target.stem}{suffix_base}_{ts}{target.suffix}")
    else:
        return target.with_name(f"{target.name}{suffix_base}_{ts}")

def _merge_move_with_dedup(src: Path, dst: Path):
    """
    Unisce ricorsivamente i contenuti di 'src' dentro 'dst'.
    - Se collisione su directory: merge.
    - Se collisione su file:
        * se contenuto identico: scarta il duplicato (elimina 'src')
        * se diverso: rinomina il nuovo con suffisso _conflict_<timestamp>
    Alla fine rimuove 'src'.
    """
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            # Merge directory
            target.mkdir(exist_ok=True)
            _merge_move_with_dedup(item, target)
            try:
                item.rmdir()
            except Exception:
                shutil.rmtree(item, ignore_errors=True)
        else:
            if target.exists():
                if target.is_file():
                    # Conflitto di file
                    if files_equal(item, target):
                        # Identico: elimina duplicato
                        item.unlink(missing_ok=True)
                    else:
                        # Diverso: rinomina il nuovo e sposta
                        new_target = unique_collision_name(target, "_conflict")
                        shutil.move(str(item), str(new_target))
                else:
                    # 'target' è directory: rinomina file sorgente
                    new_target = unique_collision_name(dst / item.name, "_conflict")
                    shutil.move(str(item), str(new_target))
            else:
                # Nessun conflitto: sposta normalmente
                shutil.move(str(item), str(target))
    # Prova a rimuovere la sorgente (ora dovrebbe essere vuota)
    try:
        src.rmdir()
    except Exception:
        shutil.rmtree(src, ignore_errors=True)

def collapse_single_wrappers(root: Path):
    """
    Appiattisce wrapper inutili:
    - Se una cartella contiene un'unica directory e nessun file, porta i contenuti su.
    Ripete finché non ci sono più wrapper.
    """
    changed = True
    while changed:
        changed = False
        for d in list(root.rglob("*")):
            if d.is_dir():
                children = list(d.iterdir())
                files = [c for c in children if c.is_file()]
                dirs  = [c for c in children if c.is_dir()]
                if len(dirs) == 1 and len(files) == 0:
                    inner = dirs[0]
                    # Sposta contenuti dell'unica dir verso 'd'
                    for c in inner.iterdir():
                        shutil.move(str(c), str(d / c.name))
                    try:
                        inner.rmdir()
                        changed = True
                    except Exception:
                        pass

# --- Verifica ed estrazione .p7m ------------------------------------------
def extract_signed_content(p7m_path: Path, out_dir: Path) -> tuple[Path | None, str, bool]:
    base        = p7m_path.stem
    payload_out = out_dir / base
    cert_pem    = out_dir / f"{base}_cert.pem"
    chain_pem   = out_dir / f"{base}_chain.pem"

    # Estrai certificato firmatario
    subprocess.run([
        "openssl", "pkcs7", "-inform", "DER", "-in", str(p7m_path),
        "-print_certs", "-out", str(cert_pem)
    ], capture_output=True)

    # Verify catena
    cmd1 = ["openssl", "verify", "-CAfile", str(TRUST_PEM)]
    if platform.system() in ("Linux", "Darwin"):
        cmd1 += ["-CApath", "/etc/ssl/certs"]
    cmd1.append(str(cert_pem))
    p1 = subprocess.run(cmd1, capture_output=True, text=True)
    stderr1 = p1.stderr.lower()
    chain_ok = (p1.returncode == 0) or ("self signed certificate in certificate chain" in stderr1)

    # Accetta InfoCamere
    ic_hit = ("infocamere" in stderr1) or ("infocamere" in p1.stdout.lower())
    if ic_hit:
        chain_ok = True

    # Estrazione payload (anche se non valido)
    resc = subprocess.run([
        "openssl", "cms", "-verify", "-in", str(p7m_path),
        "-inform", "DER", "-noverify", "-out", str(payload_out)
    ], capture_output=True)
    if resc.returncode != 0:
        cert_pem.unlink(missing_ok=True)
        chain_pem.unlink(missing_ok=True)
        return None, "", False

    # Se il payload è ZIP, rinomina .zip
    try:
        with open(payload_out, "rb") as f:
            if f.read(4) == b"PK\x03\x04":
                newz = payload_out.with_suffix(".zip")
                payload_out.rename(newz)
                payload_out = newz
    except Exception:
        pass

    # Lettura firmatario (best-effort)
    signer = "Sconosciuto"
    res2 = subprocess.run([
        "openssl", "x509", "-in", str(cert_pem),
        "-noout", "-subject", "-dates"
    ], capture_output=True, text=True)
    cert_pem.unlink(missing_ok=True)
    chain_pem.unlink(missing_ok=True)
    if res2.returncode == 0:
        subj  = res2.stdout
        m     = re.search(r"(?:CN|SN|UID|emailAddress|SERIALNUMBER)\s*=\s*([^,\/]+)", subj)
        signer = m.group(1).strip() if m else "Sconosciuto"

    # Flag NONVALIDO se catena non accettata
    if not chain_ok:
        invalid_signatures.append(f"{payload_out.name} | {signer}")
        flagged = payload_out.with_name(payload_out.stem + "_NONVALIDO" + payload_out.suffix)
        payload_out.rename(flagged)
        payload_out = flagged

    return payload_out, signer, chain_ok

# --- Estrazione ZIP annidati con flatten + dedup ---------------------------
def recursive_extract_flat_into(target_dir: Path):
    """
    Estrae TUTTI gli ZIP (anche annidati) dentro 'target_dir' appiattendo la struttura:
    - Per ogni .zip trovato: estrai in una cartella temporanea, poi MERGE nel target con dedup.
    - Elimina il .zip dopo l'estrazione.
    - Ripeti finché non restano ZIP.
    - Appiattisci wrapper inutili alla fine.
    """
    while True:
        zips = [z for z in target_dir.rglob("*.zip") if z.is_file()]
        if not zips:
            break

        for z in zips:
            tmp_extract = Path(tempfile.mkdtemp(prefix="unz_"))
            try:
                with zipfile.ZipFile(z) as zf:
                    st.write(f"Estrazione ZIP: {z}")
                    # Debug: mostra contenuto zip
                    try:
                        st.write({"contenuto": zf.namelist()[:10], "totale": len(zf.namelist())})
                    except Exception:
                        pass
                    zf.extractall(tmp_extract)
            except Exception as e:
                st.error(f"Errore unzip annidato: {e.__class__.__name__}: {e}")
                st.code(''.join(traceback.format_exc()))
                shutil.rmtree(tmp_extract, ignore_errors=True)
                continue

            # Merge con dedup nel livello corrente
            _merge_move_with_dedup(tmp_extract, z.parent)

            # Rimuovi lo ZIP sorgente dopo il merge
            z.unlink(missing_ok=True)

    # Appiattisci wrapper
    collapse_single_wrappers(target_dir)

# --- Processa .p7m ---------------------------------------------------------
def process_p7m_dir(d: Path, indent=""):
    for p7m in d.rglob("*.p7m"):
        payload, signer, valid = extract_signed_content(p7m, p7m.parent)
        if not payload:
            continue
        p7m.unlink(missing_ok=True)
        st.write(f"{indent}– {payload.name} | {signer} | {'✅' if valid else '⚠️'}")
        if payload.suffix.lower() == ".zip":
            # Se il payload è ZIP, estrai e appiattisci
            try:
                with zipfile.ZipFile(payload) as zf:
                    tmp_extract = Path(tempfile.mkdtemp(prefix="unz_p7m_"))
                    zf.extractall(tmp_extract)
                # Merge nel parent
                _merge_move_with_dedup(tmp_extract, payload.parent)
                payload.unlink(missing_ok=True)
            except Exception:
                st.error(f"Errore estrazione ZIP interno di {payload.name}")
                continue
            # Processa eventuali ulteriori ZIP annidati
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
        # Normalizza nome (evita problemi con spazi e caratteri speciali)
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', original_name)
        fp = tmpd / safe_name
        fp.write_bytes(up.getbuffer())

        # Debug: caricamento
        try:
            size = fp.stat().st_size
        except Exception:
            size = -1
        st.write(f"File caricato: {safe_name}, path temporaneo: {fp}, size: {size}")

        if ext == ".zip":
            st.write(f"🔄 ZIP: {safe_name}")
            try:
                with zipfile.ZipFile(fp) as zf:
                    st.write({"contenuto": zf.namelist()[:10], "totale": len(zf.namelist())})
                    # Crea una cartella univoca di destinazione per questo upload
                    dest = root / f"{Path(safe_name).stem}_{datetime.now().strftime('%H%M%S')}"
                    dest.mkdir(parents=True, exist_ok=True)
                    # Estrai in temp e poi MERGE+DEDUP nel dest
                    tmp_extract = Path(tempfile.mkdtemp(prefix="unz_top_"))
                    zf.extractall(tmp_extract)
                    _merge_move_with_dedup(tmp_extract, dest)
            except Exception as e:
                st.error(f"Errore unzip: {e.__class__.__name__}: {e}")
                st.code(''.join(traceback.format_exc()))
                shutil.rmtree(tmpd, ignore_errors=True)
                continue

            # Ora gestisci ZIP annidati già dentro dest con flatten + dedup
            recursive_extract_flat_into(dest)

            # Processa .p7m eventualmente presenti
            process_p7m_dir(dest)

            shutil.rmtree(tmpd, ignore_errors=True)

        elif ext == ".p7m":
            st.write(f"🔄 .p7m: {safe_name}")
            payload, signer, valid = extract_signed_content(fp, root)
            if payload:
                st.write(f"– {payload.name} | {signer} | {'✅' if valid else '⚠️'}")
                if payload.suffix.lower() == ".zip":
                    # Se il payload è ZIP, estrai nel root e dedup
                    try:
                        with zipfile.ZipFile(payload) as zf:
                            tmp_extract = Path(tempfile.mkdtemp(prefix="unz_p7m_top_"))
                            zf.extractall(tmp_extract)
                        _merge_move_with_dedup(tmp_extract, root)
                        payload.unlink(missing_ok=True)
                    except Exception:
                        st.error(f"Errore estrazione ZIP da payload {payload.name}")
                    recursive_extract_flat_into(root)
            shutil.rmtree(tmpd, ignore_errors=True)

        else:
            st.warning(f"Ignoro {safe_name}")
            shutil.rmtree(tmpd, ignore_errors=True)

    # --- Creazione ZIP finale mantenendo la struttura risultante -----------
    outd = Path(tempfile.mkdtemp(prefix="zip_out_"))
    zipf = outd / output_filename
    with zipfile.ZipFile(zipf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for path in root.rglob('*'):
            if path.is_file():
                zf.write(path, path.relative_to(root))

    st.subheader("Anteprima struttura ZIP risultante")
    try:
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
    except Exception as e:
        st.error(f"Errore anteprima ZIP finale: {e}")

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
