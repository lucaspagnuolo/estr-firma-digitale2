from __future__ import annotations

import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


class UnsafeZipError(RuntimeError):
    """Errore rilevato durante la validazione o estrazione sicura di uno ZIP."""


@dataclass(frozen=True, slots=True)
class ZipLimits:
    """Limiti applicati all'estrazione degli archivi ZIP."""

    max_members: int = 10_000
    max_member_size: int = 512 * 1024 * 1024
    max_total_size: int = 2 * 1024 * 1024 * 1024
    max_compression_ratio: float = 1_000.0


_COPY_BUFFER_SIZE = 1024 * 1024


def safe_extract_zip(
    archive_path: Path,
    destination: Path,
    limits: ZipLimits | None = None,
) -> None:
    """
    Estrae uno ZIP applicando controlli di sicurezza.

    Controlla:
    - numero massimo di elementi;
    - dimensione massima del singolo elemento;
    - dimensione totale estratta;
    - rapporto di compressione anomalo;
    - ZIP cifrati;
    - path traversal;
    - percorsi assoluti;
    - link simbolici e file speciali;
    - percorsi duplicati;
    - sovrascritture;
    - dimensione effettivamente scritta su disco.

    Args:
        archive_path: ZIP da estrarre.
        destination: Directory di destinazione.
        limits: Limiti opzionali di sicurezza.

    Raises:
        UnsafeZipError: Se lo ZIP viola un controllo di sicurezza.
        FileNotFoundError: Se lo ZIP non esiste.
        zipfile.BadZipFile: Se il file non è uno ZIP valido.
        OSError: In caso di errore filesystem.
    """
    archive_path = Path(archive_path)
    destination = Path(destination)
    limits = limits or ZipLimits()

    if not archive_path.is_file():
        raise FileNotFoundError(
            f"Archivio ZIP non trovato: {archive_path}"
        )

    destination.mkdir(parents=True, exist_ok=True)
    destination = destination.resolve()

    with zipfile.ZipFile(archive_path, mode="r") as archive:
        members = _validate_archive(
            archive,
            limits,
        )

        _extract_members(
            archive=archive,
            members=members,
            destination=destination,
            limits=limits,
        )


def _validate_archive(
    archive: zipfile.ZipFile,
    limits: ZipLimits,
) -> list[zipfile.ZipInfo]:
    """Valida i metadati dello ZIP prima dell'estrazione."""

    members = archive.infolist()

    if len(members) > limits.max_members:
        raise UnsafeZipError(
            f"ZIP con troppi elementi: {len(members)} "
            f"(limite: {limits.max_members})"
        )

    total_size = 0

    for member in members:
        _validate_member_type(member)

        if member.flag_bits & 0x1:
            raise UnsafeZipError(
                f"Elemento ZIP cifrato non supportato: "
                f"{member.filename}"
            )

        if member.is_dir():
            continue

        if member.file_size > limits.max_member_size:
            raise UnsafeZipError(
                f"Elemento ZIP troppo grande: {member.filename}"
            )

        total_size += member.file_size

        if total_size > limits.max_total_size:
            raise UnsafeZipError(
                "Dimensione totale dichiarata dello ZIP "
                "oltre il limite consentito"
            )

        if member.file_size:
            compressed_size = max(member.compress_size, 1)
            ratio = member.file_size / compressed_size

            if ratio > limits.max_compression_ratio:
                raise UnsafeZipError(
                    "Rapporto di compressione anomalo per "
                    f"{member.filename}: {ratio:.1f}"
                )

    return members


def _extract_members(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    destination: Path,
    limits: ZipLimits,
) -> None:
    """
    Estrae manualmente i membri.

    La dimensione viene verificata anche durante la decompressione,
    senza fidarsi esclusivamente dei valori dichiarati nello ZIP.
    """

    seen_paths: set[str] = set()
    total_written = 0

    for member in members:
        relative_path = _safe_member_path(
            member.filename
        )

        if relative_path is None:
            continue

        target = destination.joinpath(
            *relative_path.parts
        ).resolve()

        if not target.is_relative_to(destination):
            raise UnsafeZipError(
                f"Percorso ZIP non sicuro: {member.filename}"
            )

        normalized_target = str(target).casefold()

        if normalized_target in seen_paths:
            raise UnsafeZipError(
                f"Percorso ZIP duplicato: {member.filename}"
            )

        seen_paths.add(normalized_target)

        if member.is_dir():
            target.mkdir(
                parents=True,
                exist_ok=True,
            )
            continue

        if target.exists():
            raise UnsafeZipError(
                f"Il file di destinazione esiste già: {target}"
            )

        target.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        member_written = 0

        try:
            with (
                archive.open(member, mode="r") as source,
                target.open(mode="xb") as output,
            ):
                while chunk := source.read(_COPY_BUFFER_SIZE):
                    member_written += len(chunk)
                    total_written += len(chunk)

                    if member_written > limits.max_member_size:
                        raise UnsafeZipError(
                            "Elemento ZIP oltre il limite reale: "
                            f"{member.filename}"
                        )

                    if total_written > limits.max_total_size:
                        raise UnsafeZipError(
                            "Dimensione totale realmente estratta "
                            "oltre il limite consentito"
                        )

                    output.write(chunk)

        except Exception:
            target.unlink(missing_ok=True)
            raise


def _safe_member_path(
    filename: str,
) -> PurePosixPath | None:
    """Normalizza e valida un percorso contenuto nello ZIP."""

    if "\x00" in filename:
        raise UnsafeZipError(
            "Nome ZIP contenente carattere nullo"
        )

    normalized = filename.replace("\\", "/")

    if not normalized or normalized in {".", "/"}:
        return None

    path = PurePosixPath(normalized)

    if path.is_absolute():
        raise UnsafeZipError(
            f"Percorso assoluto nello ZIP: {filename}"
        )

    safe_parts: list[str] = []

    for part in path.parts:
        if part in {"", "."}:
            continue

        if part == "..":
            raise UnsafeZipError(
                f"Path traversal rilevato nello ZIP: {filename}"
            )

        if ":" in part:
            raise UnsafeZipError(
                f"Percorso ZIP non consentito: {filename}"
            )

        safe_parts.append(part)

    if not safe_parts:
        return None

    return PurePosixPath(*safe_parts)


def _validate_member_type(
    member: zipfile.ZipInfo,
) -> None:
    """Accetta esclusivamente file regolari e directory."""

    unix_mode = member.external_attr >> 16

    if unix_mode == 0:
        return

    file_type = stat.S_IFMT(unix_mode)

    if file_type not in {
        0,
        stat.S_IFREG,
        stat.S_IFDIR,
    }:
        raise UnsafeZipError(
            f"Tipo di elemento ZIP non supportato: "
            f"{member.filename}"
        )