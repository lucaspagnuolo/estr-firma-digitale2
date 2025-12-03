
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

# Liste globali per alert
invalid_signatures = []
conflict_logs = []

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

def ensure_conflicts_dir(dst: Path) -> Path:
    cdir = dst / "_conflicts"
    cdir.mkdir(exist_ok=True)
    return cdir

# [MOD] Rilevazione tipo file (magic number)
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
    """
    Unisce ricorsivamente i contenuti di 'src' dentro 'dst'.
    - Se collisione su directory: merge.
    - Se collisione su file:
        * se contenuto identico: scarta il duplicato (elimina 'src')
        * se diverso:
            - se strategia = rinomina: rinomina nuovo con suffisso _conflict_<timestamp>
            - se strategia = cartella: sposta il nuovo in dst/_conflicts mantenendo nome originale
    Alla fine rimuove 'src'.
    """
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            target.mkdir(exist_ok=True)
            _merge_move_with_dedup(item, target)
            try:
                item.rmdir()
            except Exception:
                shutil.rmtree(item, ignore_errors=True)
        else:
            if target.exists():
                if target.is_file():
                    if files_equal(item, target):
                        # Identico: elimina duplicato silenziosamente
                        item.unlink(missing_ok=True)
                    else:
                        # Diverso: applica strategia
                        if CONFLICT_STRATEGY.startswith("Rinomina"):
                            new_target = unique_collision_name(target, "_conflict")
                            conflict_logs.append(f"Conflitto: {target} vs nuovo -> rinominato {new_target.name}")
                            shutil.move(str(item), str(new_target))
                        else:
                            cdir = ensure_conflicts_dir(dst)
                            new_target = cdir / item.name
                            # Se esiste già in _conflicts, crea variante univoca
                            if new_target.exists():
                                new_target = unique_collision_name(new_target, "_conflict")
                            conflict_logs.append(f"Conflitto: {target} vs nuovo -> spostato in {new_target}")
                            shutil.move(str(item), str(new_target))
                else:
                    # 'target' è directory: rinomina o sposta altrove il file sorgente
                    if CONFLICT_STRATEGY.startswith("Rinomina"):
                        new_target = unique_collision_name(dst / item.name, "_conflict")
                        shutil.move(str(item), str(new_target))
                    else:
                        cdir = ensure_conflicts_dir(dst)
                        new_target = cdir / item.name
                        if new_target.exists():
                            new_target = unique_collision_name(new_target, "_conflict")
                        shutil.move(str(item), str(new_target))
            else:
                shutil.move(str(item), str(target))
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
                    for c in inner.iterdir():
                        shutil.move(str(c), str(d / c.name))
                    try:
                        inner.rmdir()
                        changed = True
                    except Exception:
                        pass

# --- Verifica ed estrazione .p7m ------------------------------------------
def extract_signed_content(p7m_path: Path, out_dir: Path, rename_nonvalid: bool) -> tuple[Path | None, str, bool]:
    base        = p7m_path.stem   # es: "file.pdf" oppure "file.zip"
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

    # [MOD] Allinea estensione al tipo reale SOLO se manca o è incoerente
    try:
        if is_zip_file(payload_out):
            # Se è ZIP ma il nome non termina con .zip, aggiungilo
            if payload_out.suffix.lower() != ".zip":
                newz = payload_out.with_suffix(".zip")
                # Evita doppio .zip.zip
                if newz.name.endswith(".zip.zip"):
                    newz = Path(newz.as_posix().replace(".zip.zip", ".zip"))
                payload_out.rename(newz)
                payload_out = newz
        elif is_pdf_file(payload_out):
            # Se è PDF ma il nome non termina con .pdf, aggiungilo
            if payload_out.suffix.lower() != ".pdf":
                newpdf = payload_out.with_suffix(".pdf")
                payload_out.rename(newpdf)
                payload_out = newpdf
    except Exception:
        # Se la rename fallisce, mantieni il nome originale
        pass

    # Best-effort firmatario (non influisce sul nome)
    signer = "Sconosciuto"
    res2 = subprocess.run([
        "openssl", "x509", "-in", str(cert_pem),
        "-noout", "-subject", "-dates"
    ], capture_output=True, text=True)
    if res2.returncode == 0:
        subj  = res2.stdout
        m     = re.search(r"(?:CN|SN|UID|emailAddress|SERIALNUMBER)\s*=\s*([^,\/]+)", subj)
        signer = m.group(1).strip() if m else "Sconosciuto"

    # Pulizia temporanei cert
    cert_pem.unlink(missing_ok=True)
    chain_pem.unlink(missing_ok=True)

    # Flag: mantieni nome originale; se l'utente ha scelto, rinomina con _NONVALIDO
    if not chain_ok:
        invalid_signatures.append(f"{payload_out.name} | {signer}")
        if rename_nonvalid:
            flagged = payload_out.with_name(payload_out.stem + "_NONVALIDO" + payload_out.suffix)
            if flagged.exists():
                flagged = unique_collision_name(flagged, "_nonvalido")
            try:
                if payload_out.exists():
                    payload_out.rename(flagged)
                payload_out = flagged
            except Exception:
                pass

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
            # [MOD] Protezione extra: apri solo se è davvero ZIP
            if not is_zip_file(z):
                continue

            tmp_extract = Path(tempfile.mkdtemp(prefix="unz_"))
            try:
                with zipfile.ZipFile(z) as zf:
                    st.write(f"Estrazione ZIP: {z}")
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

            _merge_move_with_dedup(tmp_extract, z.parent)
            z.unlink(missing_ok=True)

    collapse_single_wrappers(target_dir)

# --- Processa .p7m ---------------------------------------------------------
def process_p7m_dir(d: Path, indent=""):
    for p7m in d.rglob("*.p7m"):
        payload, signer, valid = extract_signed_content(p7m, p7m.parent, RENAME_NONVALID)
        if not payload:
            continue
        p7m.unlink(missing_ok=True)
        st.write(f"{indent}– {payload.name} | {signer} | {'✅' if valid else '⚠️'}")

        # [MOD] Tenta estrazione ZIP SOLO se è davvero ZIP
        if is_zip_file(payload):
            try:
                tmp_extract = Path(tempfile.mkdtemp(prefix="unz_p7m_"))
                with zipfile.ZipFile(payload) as zf:
                    zf.extractall(tmp_extract)
                _merge_move_with_dedup(tmp_extract, payload.parent)
                payload.unlink(missing_ok=True)
            except Exception:
                st.error(f"Errore estrazione ZIP interno di {payload.name}")
                continue
            recursive_extract_flat_into(payload.parent)

# --- UI principale ---------------------------------------------------------
output_name = st.text_input("Nome ZIP di output (.zip):", value="all_extracted.zip")
output_filename = output_name if output_name.lower().endswith(".zip") else output_name + ".zip"

uploads = st.file_uploader("Carica .p7m o ZIP", accept_multiple_files=True)
if uploads:
    root = Path(tempfile.mkdtemp(prefix="combined_"))

    for up in uploads:
        original_name = up.name           # <-- nome originale per la cartella
        ext = Path(original_name).suffix.lower()
        tmpd = Path(tempfile.mkdtemp(prefix="proc_"))

        # File temporaneo sicuro (solo per salvataggio iniziale)
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', original_name)
        fp = tmpd / safe_name
        fp.write_bytes(up.getbuffer())

        # Debug: caricamento
        size = fp.stat().st_size if fp.exists() else -1
        st.write(f"File caricato: {original_name} (temp: {safe_name}), path: {fp}, size: {size}")

        if ext == ".zip":
            st.write(f"🔄 ZIP: {original_name}")
            try:
                # Il nome della cartella di destinazione è lo STEM ORIGINALE (con spazi/punti)
                dest = root / Path(original_name).stem
                dest.mkdir(parents=True, exist_ok=True)

                # Estrai in temp e poi MERGE+DEDUP nel dest mantenendo nomi originali
                tmp_extract = Path(tempfile.mkdtemp(prefix="unz_top_"))
                with zipfile.ZipFile(fp) as zf:
                    st.write({"contenuto": zf.namelist()[:10], "totale": len(zf.namelist())})
                    zf.extractall(tmp_extract)
                _merge_move_with_dedup(tmp_extract, dest)
            except Exception as e:
                st.error(f"Errore unzip: {e.__class__.__name__}: {e}")
                st.code(''.join(traceback.format_exc()))
                shutil.rmtree(tmpd, ignore_errors=True)
                continue

            # Gestisci ZIP annidati già dentro dest con flatten + dedup
            recursive_extract_flat_into(dest)

            # Processa .p7m eventualmente presenti
            process_p7m_dir(dest)

            shutil.rmtree(tmpd, ignore_errors=True)

        elif ext == ".p7m":
            st.write(f"🔄 .p7m: {original_name}")
            payload, signer, valid = extract_signed_content(fp, root, RENAME_NONVALID)
            if payload:
                st.write(f"– {payload.name} | {signer} | {'✅' if valid else '⚠️'}")
                # [MOD] Tenta estrazione ZIP SOLO se è davvero ZIP
                if is_zip_file(payload):
                    try:
                        tmp_extract = Path(tempfile.mkdtemp(prefix="unz_p7m_top_"))
                        with zipfile.ZipFile(payload) as zf:
                            zf.extractall(tmp_extract)
                        _merge_move_with_dedup(tmp_extract, root)
                        payload.unlink(missing_ok=True)
                    except Exception:
                        st.error(f"Errore estrazione ZIP da payload {payload.name}")
                    recursive_extract_flat_into(root)
            shutil.rmtree(tmpd, ignore_errors=True)

        else:
            st.warning(f"Ignoro {original_name}")
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
        st.warning("⚠️ Firme non verificate (nomi originali mantenuti):")
        for item in invalid_signatures:
            st.write(f"• {item}")

    if conflict_logs:
        st.info("ℹ️ Conflitti gestiti:")
        for msg in conflict_logs:
            st.write(f"• {msg}")

    with open(zipf, 'rb') as f:
        st.download_button(
            "Scarica estratti",
            data=f,
            file_name=output_filename,
            mime="application/zip"
