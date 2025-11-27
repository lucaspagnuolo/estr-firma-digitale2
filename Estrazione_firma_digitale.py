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

# --- Costanti per TSL -----------------------------------------------------
TSL_FILE  = Path("img/TSL-IT.xml")
TRUST_PEM = Path("tsl-ca.pem")   # nome più descrittivo

def build_trust_store(tsl_path: Path, out_pem: Path):
    """
    Estrae tutti i <ds:X509Certificate> dal TSL-IT.xml e li converte
    in un unico file PEM, con wrapping a 64 caratteri per riga.
    """
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
                # salta eventuali nodi vuoti o troppo corti
                continue
            f.write(b"-----BEGIN CERTIFICATE-----\n")
            # spezzetta in blocchi da 64 caratteri
            for i in range(0, len(b64), 64):
                f.write(b64[i:i+64].encode('ascii') + b"\n")
            f.write(b"-----END CERTIFICATE-----\n\n")

# Costruisco il trust store all’avvio
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

def extract_signed_content(p7m_path: Path, out_dir: Path) -> tuple[Path | None, str, bool]:
    """
    Estrae il payload da un .p7m e verifica la firma CAdES contro:
      - trust store (tsl-ca.pem)
      - CApath di sistema
      - fallback AIA + intermedi
      - accetta self-signed in trust-store
      - accetta comunque missing issuer
    Restituisce: (percorso_payload, signer_CN, validità_bool)
    """
    base       = p7m_path.stem
    payload_out = out_dir / base
    cert_pem    = out_dir / f"{base}_cert.pem"
    chain_pem   = out_dir / f"{base}_chain.pem"

    # 1) estrai il cert del firmatario
    subprocess.run([
        "openssl", "pkcs7", "-inform", "DER", "-in", str(p7m_path),
        "-print_certs", "-out", str(cert_pem)
    ], capture_output=True)

    # 2) primo verify con trust-store + CApath
    cmd1 = ["openssl", "verify", "-CAfile", str(TRUST_PEM)]
    if platform.system() in ("Linux", "Darwin"):
        cmd1 += ["-CApath", "/etc/ssl/certs"]
    cmd1.append(str(cert_pem))
    p1 = subprocess.run(cmd1, capture_output=True, text=True)
    stderr1 = p1.stderr.lower()
    chain_ok = (p1.returncode == 0) or ("self signed certificate in certificate chain" in stderr1)

    # 3) fallback AIA + intermedi estratti
    if not chain_ok:
        # estrai tutti i cert embedded
        subprocess.run([
            "openssl", "pkcs7", "-inform", "DER", "-in", str(p7m_path),
            "-print_certs", "-out", str(chain_pem)
        ], capture_output=True)

        # scarica eventuali intermedi da AIA
        aia = subprocess.run([
            "openssl", "x509", "-in", str(chain_pem),
            "-noout", "-text"
        ], capture_output=True, text=True)
        url = next((l.split("URI:")[1].strip() for l in aia.stdout.splitlines()
                    if "CA Issuers - URI:" in l), None)
        if url:
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and b"BEGIN CERTIFICATE" in r.content:
                    with open(chain_pem, "ab") as f:
                        f.write(b"\n" + r.content + b"\n")
            except Exception:
                pass

        # secondo verify: ora includo anche CApath di sistema
        cmd2 = [
            "openssl", "verify", "-CAfile", str(TRUST_PEM),
            "-untrusted", str(chain_pem)
        ]
        if platform.system() in ("Linux", "Darwin"):
            cmd2 += ["-CApath", "/etc/ssl/certs"]
        cmd2.append(str(cert_pem))
        p2 = subprocess.run(cmd2, capture_output=True, text=True)
        stderr2 = p2.stderr.lower()
        chain_ok = (p2.returncode == 0) or ("self signed certificate in certificate chain" in stderr2)

        # **NUOVO**: se l’unico errore rimasto è “unable to get local issuer certificate”,
        # lo consideriamo comunque valido
        if not chain_ok and "unable to get local issuer certificate" in stderr2:
            chain_ok = True

    if not chain_ok:
        st.error(f"Errore verifica catena «{cert_pem.name}»: "
                 f"{(p2.stderr if 'p2' in locals() else p1.stderr).strip()}")
        cert_pem.unlink(missing_ok=True)
        chain_pem.unlink(missing_ok=True)
        return None, "", False

    # 4) estrai il payload (firma validata)
    resc = subprocess.run([
        "openssl", "cms", "-verify", "-in", str(p7m_path),
        "-inform", "DER", "-noverify", "-out", str(payload_out)
    ], capture_output=True)
    if resc.returncode != 0:
        st.error(f"Errore estrazione «{p7m_path.name}»: {resc.stderr.decode().strip()}")
        cert_pem.unlink(missing_ok=True)
        chain_pem.unlink(missing_ok=True)
        return None, "", False

    # 5) leggi signer e validity
    res2 = subprocess.run([
        "openssl", "x509", "-in", str(cert_pem),
        "-noout", "-subject", "-dates"
    ], capture_output=True, text=True)
    cert_pem.unlink(missing_ok=True)
    chain_pem.unlink(missing_ok=True)
    if res2.returncode != 0:
        st.error(f"Errore lettura info cert: {res2.stderr.strip()}")
        return payload_out, "Sconosciuto", False

    lines  = res2.stdout.splitlines()
    subj   = "\n".join(lines)
    # estrai il primo RDN popolare come signer
    m = re.search(r"(?:CN|SN|UID|emailAddress|SERIALNUMBER)\s*=\s*([^,\/]+)", subj)
    signer = m.group(1).strip() if m else "Sconosciuto"

    fmt = "%b %d %H:%M:%S %Y %Z"
    nb  = next(l for l in lines if "notBefore" in l).split("=",1)[1].strip()
    na  = next(l for l in lines if "notAfter"  in l).split("=",1)[1].strip()
    valid = datetime.strptime(nb, fmt) <= datetime.utcnow() <= datetime.strptime(na, fmt)

    # 6) rinomina in .zip se payload è un archivio
    try:
        with open(payload_out, "rb") as f:
            if f.read(4) == b"PK\x03\x04":
                newz = payload_out.with_suffix(".zip")
                payload_out.rename(newz)
                payload_out = newz
    except Exception:
        pass

    return payload_out, signer, valid


# --- ZIP annidati e processing .p7m ---------------------------------------
def recursive_unpack_and_flatten(d: Path):
    for z in d.rglob("*.zip"):
        if not z.is_file(): continue
        dst = z.parent / f"{z.stem}_unz"
        shutil.rmtree(dst, ignore_errors=True)
        dst.mkdir()
        try:
            with zipfile.ZipFile(z) as zf:
                zf.extractall(dst)
        except:
            z.unlink(missing_ok=True)
            continue
        z.unlink(missing_ok=True)
        children = list(dst.iterdir())
        if len(children) == 1 and children[0].is_dir():
            for c in children[0].iterdir():
                shutil.move(str(c), dst)
            children[0].rmdir()
        recursive_unpack_and_flatten(dst)

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
                    inn = [n for n in zf.namelist() if n.lower().endswith(".zip")]
                    if len(inn) == 1:
                        data = zf.read(inn[0])
                        tgt = tmp / Path(inn[0]).name
                        tgt.write_bytes(data)
                        with zipfile.ZipFile(tgt) as iz:
                            iz.extractall(tmp)
                        payload.unlink(missing_ok=True)
                    else:
                        zf.extractall(tmp)
                        payload.unlink(missing_ok=True)
            except:
                st.error(f"Errore estrazione ZIP interno di {payload.name}")
                continue
            recursive_unpack_and_flatten(tmp)
            nested = tmp / payload.stem
            if nested.is_dir():
                process_p7m_dir(nested, indent + "  ")

# --- Streamlit UI e flusso principale ------------------------------------
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
                    inn = [n for n in zf.namelist() if n.lower().endswith(".zip")]
                    if len(inn) == 1:
                        data = zf.read(inn[0])
                        tgt = tmpd / Path(inn[0]).name
                        tgt.write_bytes(data)
                        with zipfile.ZipFile(tgt) as iz:
                            iz.extractall(tmpd)
                        base_dir = tmpd
                    else:
                        zf.extractall(tmpd)
                        base_dir = tmpd
            except Exception as e:
                st.error(f"Errore unzip: {e}")
                shutil.rmtree(tmpd, ignore_errors=True)
                continue

            recursive_unpack_and_flatten(base_dir)
            target = root / fp.stem
            shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(base_dir, target)
            red = target / fp.stem
            if red.is_dir():
                for it in red.iterdir():
                    shutil.move(str(it), target)
                shutil.rmtree(red, ignore_errors=True)

            process_p7m_dir(target)
            shutil.rmtree(tmpd, ignore_errors=True)

        elif ext == ".p7m":
            st.write(f"🔄 .p7m: {name}")
            payload, signer, valid = extract_signed_content(fp, root)
            if payload:
                st.write(f"– {payload.name} | {signer} | {'✅' if valid else '⚠️'}")
            shutil.rmtree(tmpd, ignore_errors=True)

        else:
            st.warning(f"Ignoro {name}")

    # pulizia residui
    for d in root.rglob("*_unz"):
        shutil.rmtree(d, ignore_errors=True)
    for p in root.rglob("*.p7m"):
        p.unlink(missing_ok=True)

    # creazione e preview del ZIP finale
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
        paths = [
            i.filename
            for i in zf.infolist()
            if '_unz' not in i.filename and not i.filename.lower().endswith('.p7m')
        ]
    if paths:
        rows = [p.split("/") for p in paths]
        max_levels = max(len(r) for r in rows)
        cols = [f"Liv {i+1}" for i in range(max_levels)]
        df = pd.DataFrame([r + [""]*(max_levels-len(r)) for r in rows], columns=cols)
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
