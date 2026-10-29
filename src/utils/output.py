import tempfile
import zipfile
from pathlib import Path
from src.data_class.p7m import P7MUnwrapResult

def create_output_zip(
    result: P7MUnwrapResult,
    output_filename: str,
) -> Path:
    """
    Crea lo ZIP finale a partire dal payload restituito
    dall'estrazione P7M.

    La struttura delle directory viene preservata.

    Args:
        result: Risultato dell'estrazione ricorsiva.
        output_filename: Nome dello ZIP finale.

    Returns:
        Path dello ZIP generato.
    """

    if result.payload is None:
        raise ValueError("Nessun payload disponibile.")

    payload = result.payload

    out_dir = Path(tempfile.mkdtemp(prefix="zip_out_"))
    zip_path = out_dir / output_filename

    with zipfile.ZipFile(
        zip_path,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as zf:

        # Caso 1: il payload è una directory
        if payload.is_dir():

            for file in payload.rglob("*"):

                if not file.is_file():
                    continue

                zf.write(
                    file,
                    file.relative_to(payload),
                )

        # Caso 2: il payload è un singolo file
        else:

            zf.write(
                payload,
                payload.name,
            )

    return zip_path