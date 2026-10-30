from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from src.data_class.p7m import ExtractedItem, P7MUnwrapResult
from src.services.P7MExtractor import P7MExtractor
from src.services.ZipCreator import ZipCreator


CASES_DIR = Path(__file__).parent / "cases"
RESULTS_DIR = Path(__file__).parent / "results"


def _case_number(path: Path) -> tuple[int, str]:
    """Ordina test2 prima di test10 e gestisce anche nomi non standard."""
    suffix = path.name.removeprefix("test")
    return (int(suffix), path.name) if suffix.isdigit() else (10**9, path.name)


def _discover_cases() -> list[Path]:
    """Restituisce tests/cases/test1, test2, ... in ordine numerico."""
    if not CASES_DIR.is_dir():
        return []

    return sorted(
        (
            path
            for path in CASES_DIR.iterdir()
            if path.is_dir()
            and path.name.startswith("test")
            and path.name.removeprefix("test").isdigit()
        ),
        key=_case_number,
    )


def _filesystem_tree(root: Path) -> list[str]:
    """Rappresenta una directory reale con un albero testuale stabile."""
    lines = [f"{root.name}/"]

    def visit(directory: Path, prefix: str) -> None:
        entries = sorted(
            directory.iterdir(),
            key=lambda item: (not item.is_dir(), item.name.casefold()),
        )

        for index, entry in enumerate(entries):
            last = index == len(entries) - 1
            branch = "└── " if last else "├── "
            lines.append(f"{prefix}{branch}{entry.name}{'/' if entry.is_dir() else ''}")

            if entry.is_dir():
                visit(entry, prefix + ("    " if last else "│   "))

    visit(root, "")
    return lines


def _zip_tree(zip_path: Path) -> list[str]:
    """Rappresenta la struttura logica contenuta nello ZIP prodotto."""
    tree: dict[str, dict] = {}

    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            parts = [part for part in PurePosixPath(info.filename).parts if part]
            node = tree
            for part in parts:
                node = node.setdefault(part, {})

    lines = [f"{zip_path.name}/"]

    def visit(node: dict[str, dict], prefix: str) -> None:
        entries = sorted(node.items(), key=lambda item: item[0].casefold())
        for index, (name, children) in enumerate(entries):
            last = index == len(entries) - 1
            branch = "└── " if last else "├── "
            lines.append(f"{prefix}{branch}{name}{'/' if children else ''}")
            if children:
                visit(children, prefix + ("    " if last else "│   "))

    visit(tree, "")
    return lines


def _extract_case(
    case_dir: Path,
    extractor: P7MExtractor,
    work_dir: Path,
) -> P7MUnwrapResult:
    """Elabora tutti gli elementi della cartella mantenendo la gerarchia."""
    root = ExtractedItem(
        name=case_dir.name,
        kind="directory",
    )

    def process_directory(source_dir: Path, destination_node: ExtractedItem) -> None:
        entries = sorted(
            source_dir.iterdir(),
            key=lambda item: (not item.is_dir(), item.name.casefold()),
        )

        for entry in entries:
            if entry.is_dir():
                child = ExtractedItem(name=entry.name, kind="directory")
                destination_node.children.append(child)
                process_directory(entry, child)
                continue

            if not entry.is_file():
                destination_node.children.append(
                    ExtractedItem(
                        name=entry.name,
                        kind="file",
                        error="Tipo di elemento non supportato nel test",
                    )
                )
                continue

            item_work_dir = work_dir / entry.relative_to(case_dir).parent
            item_work_dir.mkdir(parents=True, exist_ok=True)
            result = extractor.extract(entry, item_work_dir)
            destination_node.children.append(result.root)

    process_directory(case_dir, root)
    return P7MUnwrapResult(root=root)


def _collect_errors(item: ExtractedItem, parent: str = "") -> list[str]:
    """Raccoglie gli errori presenti nell'albero restituito dalla pipeline."""
    current = f"{parent}/{item.name}" if parent else item.name
    errors = [f"{current}: {item.error}"] if item.error else []

    for child in item.children:
        errors.extend(_collect_errors(child, current))

    return errors


def _assert_no_p7m_in_output(zip_path: Path) -> None:
    """Sanity check: nello ZIP finale non devono restare wrapper .p7m."""
    with zipfile.ZipFile(zip_path) as archive:
        residual = [
            info.filename
            for info in archive.infolist()
            if not info.is_dir() and info.filename.casefold().endswith(".p7m")
        ]

    assert not residual, f"P7M non sfirmati nell'output: {residual}"


def test_pipeline_cases(tmp_path: Path) -> None:
    """
    Esegue tutti i casi testN e produce un report per la verifica umana.

    Output persistenti:
        tests/results/testN/output.zip
        tests/results/testN/INPUT_TREE.txt
        tests/results/testN/OUTPUT_TREE.txt
    """
    cases = _discover_cases()
    assert cases, f"Nessun caso trovato in {CASES_DIR}"


    extractor = P7MExtractor()
    creator = ZipCreator()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []

    for case_dir in cases:
        case_result_dir = RESULTS_DIR / case_dir.name
        shutil.rmtree(case_result_dir, ignore_errors=True)
        case_result_dir.mkdir(parents=True)

        input_tree = _filesystem_tree(case_dir)
        work_dir = tmp_path / case_dir.name / "work"
        work_dir.mkdir(parents=True)

        try:
            result = _extract_case(case_dir, extractor, work_dir)
            extraction_errors = _collect_errors(result.root)
            if extraction_errors:
                raise AssertionError("; ".join(extraction_errors))

            temporary_zip = creator(result, f"{case_dir.name}_output.zip")
            output_zip = case_result_dir / "output.zip"
            shutil.copy2(temporary_zip, output_zip)

            _assert_no_p7m_in_output(output_zip)
            output_tree = _zip_tree(output_zip)

            (case_result_dir / "INPUT_TREE.txt").write_text(
                "\n".join(input_tree) + "\n",
                encoding="utf-8",
            )
            (case_result_dir / "OUTPUT_TREE.txt").write_text(
                "\n".join(output_tree) + "\n",
                encoding="utf-8",
            )

            print(f"\n{'=' * 72}")
            print(f"CASO: {case_dir.name}")
            print("\nINPUT")
            print("\n".join(input_tree))
            print("\nOUTPUT")
            print("\n".join(output_tree))
            print(f"\nZIP: {output_zip}")

        except Exception as exc:  # continua per mostrare tutti i casi falliti
            failures.append(f"{case_dir.name}: {type(exc).__name__}: {exc}")

    assert not failures, "Pipeline fallita:\n- " + "\n- ".join(failures)
