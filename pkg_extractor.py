import hashlib
import hmac
import json
import os
import queue
import struct
import sys
import threading
import tempfile
import time
import weakref
from array import array
from contextlib import contextmanager
from functools import lru_cache
from itertools import pairwise
from pathlib import Path, PureWindowsPath
import zlib


_FROZEN = bool(getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"))
_ORIGINAL_CWD = os.getcwd()
if _FROZEN:
    os.environ["TCL_LIBRARY"] = "_tcl_data"
    os.environ["TK_LIBRARY"] = "_tk_data"
    os.chdir(sys._MEIPASS)


def _application_directory():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:
    tk = None
finally:
    if _FROZEN:
        os.chdir(_ORIGINAL_CWD)

try:
    from Crypto.Cipher import AES
    from Crypto.Util.strxor import strxor
except ImportError:
    AES = None

BLOCK = 0x1000
SBLOCK = 0x10000
RESUME_DIRECTORY = ".pkg-extractor"
MAX_RESUME_BYTES = 16 * 1024 * 1024
MAGIC_PKG = 0x7F434E54
MAGIC_PFSC = 0x43534650

PFS_FILE = 2
PFS_DIR = 3
PFS_CURRENT_DIR = 4
PFS_PARENT_DIR = 5


def _progress_percent(done, total):
    if total <= 0:
        return 100.0
    return max(0.0, min(100.0, 100.0 * done / total))

KEYSET_FAKE = {
    "p": int.from_bytes(
        bytes.fromhex("FEF6BF1D69AB16250847556B86E43588"
                      "722AB13DF8B644CAB3AB19D10424280A"
                      "7455B8154509CC131CF2BA37A903908F"
                      "0210FF257986CC18509A105F5B4C1C4E"
                      "B0A7E359B12DA0C6B0202C213312B3AF"
                      "723483CD522FAF0F205A1BC0E2A37634"
                      "0FD7FCC141C9F979401742213E9DFDC7"
                      "C150DE445AC931896A7805BE65B4E82D"), "big"),
    "q": int.from_bytes(
        bytes.fromhex("C79E4758007D6282B0D22281D4A8971B"
                      "790C3AB0D7C930E3C3538E57EFF09B9F"
                      "B39052C6942236AAE64A5F721D70E876"
                      "58C8B291CE9CC3E9097F2E4797CC9039"
                      "153531DE1F0C8C0DC1C292BE97BF2F91"
                      "A18C7D50A8212FD7A29A7EB5A72A9002"
                      "D9F33DD1EBB8E05A799E7D8DCA186DBD"
                      "9EA180286B2AFE51249B6F4D84778023"), "big"),
}
KEYSET_FAKE["n"] = KEYSET_FAKE["p"] * KEYSET_FAKE["q"]
KEYSET_FAKE["d"] = pow(0x10001, -1, (KEYSET_FAKE["p"] - 1) * (KEYSET_FAKE["q"] - 1))

KEYSET_DK3 = {
    "p": int.from_bytes(
        bytes.fromhex("F967AD9912310C56A22E161C46B34D5B"
                      "43BE42A2F686968042C3C73FC342F587"
                      "49339F075D6E2C04FDE3E1B2AE0A0CF0"
                      "C7A61CA16350C8099C5124526C5E5EBD"
                      "1E2706BBBC9E94E135D46DB3CB3C68DD"
                      "68B3FE6CCB8D8220762363B7E9681001"
                      "4EDCBA275D01C12D805E2BAF826BD884"
                      "B6105286A7898EAE9AE289C6F7D587FB"), "big"),
    "q": int.from_bytes(
        bytes.fromhex("D7A10F9A8BF2C91195329A8CF0D94047"
                      "F568A00DBDC1FC432F65F9C3610F2577"
                      "54ADD758AC8440608D3FF3658975B5C6"
                      "2C511A2F1F22E4431154BEC9B4C7B51B"
                      "050BBC569ACD4AD973685E5CFB92B78B"
                      "0DFFF507CAB4C89B963C079E3E6B2A11"
                      "F28AB18AD72E1BA5532406ED50B89067"
                      "B1E241C69201EE10F061BBFBB27D4A73"), "big"),
}
KEYSET_DK3["n"] = KEYSET_DK3["p"] * KEYSET_DK3["q"]
KEYSET_DK3["d"] = pow(0x10001, -1, (KEYSET_DK3["p"] - 1) * (KEYSET_DK3["q"] - 1))


def _rsa_decrypt(keyset, ciphertext, out_len=32):
    n, d = keyset["n"], keyset["d"]
    c = int.from_bytes(ciphertext, "big")
    if c >= n:
        raise ValueError("bloco RSA fora do módulo")
    if "p" in keyset and "q" in keyset:
        p, q = keyset["p"], keyset["q"]
        left = pow(c, d % (p - 1), p)
        right = pow(c, d % (q - 1), q)
        decoded = right + q * ((left - right) * pow(q, -1, p) % p)
    else:
        decoded = pow(c, d, n)
    m = decoded.to_bytes(256, "big")
    if m[:2] != b"\x00\x02":
        raise ValueError("desembrulho RSA inválido")
    idx = m.find(b"\x00", 2)
    if idx < 10:
        raise ValueError("preenchimento RSA inválido")
    data = m[idx + 1:]
    if len(data) < out_len:
        raise ValueError("desembrulho RSA curto")
    if len(data) != out_len:
        data = data[-out_len:]
    return data


def _gfmul(t_le):
    t = t_le << 1
    if (t >> 128) & 1:
        t = (t & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF) ^ 0x87
    return t


@lru_cache(maxsize=1)
def _xts_mask_tables():
    tables = []
    for shift in range(0, 128, 6):
        basis = []
        for bit in range(min(6, 128 - shift)):
            value = 1 << (shift + bit)
            masks = []
            for _ in range(BLOCK // 16):
                masks.append(value.to_bytes(16, "little"))
                value = _gfmul(value)
            basis.append(int.from_bytes(b"".join(masks), "little"))
        table = [0]
        for value in range(1, 1 << len(basis)):
            lowest = value & -value
            table.append(table[value ^ lowest] ^ basis[lowest.bit_length() - 1])
        tables.append(tuple(table))
    return tuple(tables)


def _entry_names():
    nm = {
        0x1: "digests", 0x10: "entry_keys", 0x20: "image_key", 0x80: "general_digests",
        0x100: "metas", 0x200: "entry_names",
        0x400: "license.dat", 0x401: "license.info", 0x402: "nptitle.dat",
        0x403: "npbind.dat", 0x404: "selfinfo.dat", 0x406: "imageinfo.dat",
        0x407: "target-deltainfo.dat", 0x408: "origin-deltainfo.dat",
        0x409: "psreserved.dat",
        0x1000: "param.sfo", 0x1001: "playgo-chunk.dat", 0x1002: "playgo-chunk.sha",
        0x1003: "playgo-manifest.xml", 0x1004: "pronunciation.xml",
        0x1005: "pronunciation.sig", 0x1006: "pic1.png", 0x1007: "pubtoolinfo.dat",
        0x1008: "app/playgo-chunk.dat", 0x1009: "app/playgo-chunk.sha",
        0x100A: "app/playgo-manifest.xml", 0x100B: "shareparam.json",
        0x100C: "shareoverlayimage.png", 0x100D: "save_data.png",
        0x100E: "shareprivacyguardimage.png",
        0x1200: "icon0.png", 0x1220: "pic0.png", 0x1240: "snd0.at9",
        0x1280: "icon0.dds", 0x12A0: "pic0.dds", 0x12C0: "pic1.dds",
    }
    for i in range(0x1201, 0x1220):
        nm[i] = "icon0_%02d.png" % (i - 0x1201)
    for i in range(0x1241, 0x1260):
        nm[i] = "pic1_%02d.png" % (i - 0x1241)
    nm[0x1260] = "changeinfo/changeinfo.xml"
    for i in range(0x1261, 0x1280):
        nm[i] = "changeinfo/changeinfo_%02d.xml" % (i - 0x1261)
    for i in range(0x1281, 0x12A0):
        nm[i] = "icon0_%02d.dds" % (i - 0x1281)
    for i in range(0x12C1, 0x12E0):
        nm[i] = "pic1_%02d.dds" % (i - 0x12C1)
    for i in range(0x1400, 0x1464):
        nm[i] = "trophy/trophy%02d.trp" % (i - 0x1400)
    for k in range(10):
        nm[0x1600 + k] = "keymap_rp/%03d.png" % (k + 1)
    for g in range(30):
        base = 0x1610 + g * 0x10
        for k in range(10):
            nm[base + k] = "keymap_rp/%02d/%03d.png" % (g, k + 1)
    return nm


ENTRY_NAMES = _entry_names()
META_SKIP = {0x1, 0x10, 0x20, 0x80, 0x100, 0x200}
DEFAULT_MERGE_UPDATE = True


def _read_exact(stream, size, error_message, check=None):
    if check is None:
        data = stream.read(size)
    else:
        chunks = []
        remaining = size
        while remaining:
            check()
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError(error_message)
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    if len(data) != size:
        raise ValueError(error_message)
    return data


def _read_pkg_entries(stream, offset, count, file_size, check):
    if offset + count * 32 > file_size:
        raise ValueError("tabela de arquivos fora dos limites do pacote")
    for start in range(0, count, 2048):
        check()
        stream.seek(offset + start * 32)
        raw = _read_exact(stream, min(2048, count - start) * 32, "tabela de arquivos truncada")
        for record in struct.iter_unpack(">8I", raw):
            check()
            if record[4] + record[5] > file_size:
                raise ValueError("entrada fora dos limites do pacote")
            yield record[:6], struct.pack(">8I", *record)


def _safe_join(root, *parts):
    root = Path(root).resolve()
    candidate = root
    for part in parts:
        raw = os.fspath(part)
        path_part = Path(raw)
        windows_part = PureWindowsPath(raw)
        if (not raw or raw == "." or path_part.is_absolute() or windows_part.drive
                or windows_part.root or any(c in raw for c in '\x00<>:"|?*')
                or any(ord(c) < 32 for c in raw)):
            raise ValueError("caminho interno inválido")
        if any(piece in (".", "..") or piece.endswith((".", " "))
               or PureWindowsPath(piece).is_reserved() for piece in windows_part.parts):
            raise ValueError("caminho interno inválido")
        candidate /= path_part

    candidate = candidate.resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("caminho de saída fora da pasta escolhida")
    return candidate


def _file_stamp(path):
    info = Path(path).stat()
    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)


def _version_sort_key(value):
    return tuple(
        int(part) if part.isdigit() else 0
        for part in str(value or "0").replace("-", ".").split(".")
    )


def _pkg_sort_key(item):
    order_weight = {"base": 1, "update": 2, "dlc": 3, "other": 4}
    return (
        item.get("title_id", ""),
        order_weight.get(item.get("kind"), 5),
        _version_sort_key(item.get("app_ver")),
        item.get("filename", "").lower(),
    )


def _package_display_key(item):
    title_id, kind, version, filename = _pkg_sort_key(item)
    return kind, version if item.get("kind") == "update" else (), title_id, version, filename


LANGUAGE_TEXT = {
    "pt": {
        "title": "Easy PKG Extractor — Extrator e organizador de PKG",
        "language_button": "🌐 English",
        "add_files_frame": " 📂 Adicionar Arquivos .pkg ",
        "hint": "👉 Arraste e solte seus arquivos .pkg aqui diretamente da sua pasta\n"
                "O programa identifica Jogo Base, Atualização ou DLC e organiza os arquivos para facilitar o uso no Launcher.",
        "scan_folder": "🔍 Buscar .pkg nesta pasta",
        "add_files": "➕ Adicionar arquivos...",
        "add_folder": "📁 Adicionar outra pasta...",
        "clear_list": "🗑️ Limpar lista",
        "detected_frame": " 📋 Arquivos Detectados e Analisados ",
        "history_frame": " Histórico de Atividades ",
        "column_type": "Tipo",
        "column_title": "Título do Jogo",
        "column_code": "Código",
        "column_version": "Versão",
        "column_size": "Tamanho",
        "column_file": "Arquivo",
        "column_status": "Status",
        "destination": "Pasta de saída (será criada uma subpasta .NomeDoJogo):",
        "choose_folder": "Escolher pasta...",
        "selection_frame": " Quais pacotes extrair? ",
        "all_packages": "Todos os pacotes da lista",
        "selected_packages": "Somente os pacotes selecionados",
        "selection_hint": "Selecione na lista acima. Vários: Ctrl + clique.",
        "organization_frame": " Como organizar? ",
        "merge_update": "Juntar jogo e atualização",
        "merge_help": "Na mesma pasta. DLCs separados em addcont.",
        "extract_here": "Extrair na pasta do programa",
        "extract_here_help": "Ignora o destino acima e não cria subpasta do jogo.",
        "after_frame": " Após a extração ",
        "delete_pkg": "Apagar os .pkg após extrair com sucesso",
        "delete_help": "Remove os originais. Desmarcado = manter.",
        "extract": "🚀 Extrair e Organizar",
        "extract_selected": "Extrair pacotes selecionados",
        "cancel": "⏹ Cancelar",
        "cpu": "CPU:",
        "waiting": "Aguardando arquivos .pkg...",
        "list_cleared": "Lista limpa. Arraste novos arquivos .pkg.",
        "wait_current_operation": "Aguarde o fim da operação atual para adicionar arquivos.",
        "scanning": "Buscando e analisando os pacotes...",
        "searching_from": "Buscando arquivos .pkg em todas as pastas e subpastas a partir de: {path}...",
        "queue_status": "{count} arquivo(s) na fila. Clique em 'Extrair e Organizar'.",
        "no_packages": "Nenhum arquivo .pkg encontrado.",
        "file_not_found": "arquivo não encontrado",
        "choose_files_title": "Escolha um ou mais arquivos .pkg",
        "pkg_files": "Arquivos .pkg de PS4",
        "all_files": "Todos os arquivos",
        "choose_folder_title": "Escolha uma pasta contendo arquivos .pkg",
        "choose_output_title": "Escolha a pasta de destino",
        "choose_package_title": "Escolha o pacote",
        "choose_package_message": "Selecione os pacotes desejados na lista e depois clique em 'Extrair pacotes selecionados'.",
        "error": "Erro",
        "choose_output_message": "Escolha uma pasta de saída válida.",
        "invalid_destination": "Destino inválido",
        "different_games": "Jogos diferentes precisam de pastas separadas. Desmarque 'Extrair aqui'.",
        "cancel_requested": "Cancelamento solicitado. Aguarde...",
        "added": "Adicionado(s) {count} arquivo(s) .pkg para extração.",
        "no_compatible": "Nenhum arquivo .pkg compatível encontrado nesta busca.",
        "duplicate_warning": "Aviso: O arquivo '{filename}' já está na lista. Ignorando repetido.",
        "read_pkg_error": "Não foi possível ler '{filename}': {error}",
        "compare_pkg_error": "Não foi possível comparar '{filename}': {error}",
        "duplicate_ignored": "Arquivo duplicado ignorado: '{filename}' é igual a '{other}'.",
        "scan_cancelled": "Busca cancelada. Os pacotes já analisados foram mantidos.",
        "scan_failed": "Não foi possível concluir a busca: {error}",
        "analyze_failed": "Erro ao analisar os pacotes: {error}",
        "no_extractable": "Nenhum pacote compatível para extrair.",
        "ignored_official": "Ignorado (oficial)",
        "official_warning": "Aviso: '{filename}' é um pacote oficial da Sony com criptografia de fábrica. Ignorado para não travar.",
        "start_extraction": "Iniciando extração de {count} arquivo(s).",
        "mode_here": "Modo: Extrair aqui (sem subpasta do jogo)",
        "mode_subfolder": "Modo: Subpasta .NomeDoJogo pelo título do jogo base",
        "destination_log": "Pasta de destino: {path}",
        "missing_source": "Aviso: '{filename}' não está mais na pasta de origem. Ignorando este pacote.",
        "base_missing": "Aviso: título do jogo base indisponível na lista; usando o código CUSA como pasta.",
        "extraction_folder": "Pasta de extração: {path}",
        "package_changed": "o pacote foi alterado desde que entrou na lista; remova e adicione o arquivo novamente",
        "completed_log": "✓ Concluído com sucesso em: {path}",
        "file_deleted": "Arquivo .pkg apagado com sucesso: {filename}",
        "file_delete_failed": "Aviso: Não foi possível apagar '{filename}': {error}",
        "none_available_log": "Nenhum pacote disponível para extrair. Adicione os arquivos novamente.",
        "cancel_log": "\n⏹ Processo cancelado pelo usuário.",
        "error_log": "\n❌ ERRO durante a extração: {error}",
        "extract_error_title": "Erro na Extração",
        "extract_error_message": "Ocorreu um erro:\n{error}",
        "preparing": "[{index}/{total}] Preparando: {filename}...",
        "extracting": "[{index}/{total}] Extraindo: {filename} (0.0%)",
        "progress": "[{index}/{total}] {filename}: {percent:.1f}% ({done:.1f} MB de {total_mb:.1f} MB)",
        "completed_file": "[{index}/{total}] Concluído: {filename}",
        "success": "Extração concluída com sucesso!",
        "partial_success": "Extração finalizada: {completed}/{total} pacotes extraídos. Confira os avisos no histórico.",
        "selected_success_log": "\nPacotes selecionados extraídos com sucesso.",
        "all_success_log": "\nTodos os arquivos foram extraídos e organizados.",
        "launcher_help": "Os arquivos foram extraídos e organizados para facilitar o uso no Launcher.",
        "selected_success": "Os pacotes selecionados foram extraídos por completo.",
        "all_success": "Extração e organização concluídas com sucesso!\n\nOs arquivos foram extraídos e organizados para facilitar o uso no Launcher.",
        "cancelled": "Extração cancelada.",
        "missing_file": "Arquivo ausente",
        "extracting_status": "Extraindo...",
        "completed_status": "Concluído",
        "cancelled_status": "Cancelado",
        "error_status": "Erro",
        "ready_status": "Pronto para extrair",
        "official_status": "Criptografia oficial",
        "base_type": "Jogo Base",
        "update_type": "Atualização",
        "dlc_type": "DLC / Extra",
        "other_type": "Outro pacote",
    },
    "en": {
        "title": "Easy PKG Extractor — PKG extractor and organizer",
        "language_button": "🌐 Português",
        "add_files_frame": " 📂 Add .pkg Files ",
        "hint": "👉 Drag and drop your .pkg files here directly from their folder\n"
                "The program identifies Base Game, Update, or DLC and organizes the files for easy Launcher use.",
        "scan_folder": "🔍 Search .pkg in this folder",
        "add_files": "➕ Add files...",
        "add_folder": "📁 Add another folder...",
        "clear_list": "🗑️ Clear list",
        "detected_frame": " 📋 Detected and Analyzed Files ",
        "history_frame": " Activity History ",
        "column_type": "Type",
        "column_title": "Game Title",
        "column_code": "Code",
        "column_version": "Version",
        "column_size": "Size",
        "column_file": "File",
        "column_status": "Status",
        "destination": "Output folder (a .GameName subfolder will be created):",
        "choose_folder": "Choose folder...",
        "selection_frame": " Which packages to extract? ",
        "all_packages": "All packages in the list",
        "selected_packages": "Selected packages only",
        "selection_hint": "Select packages above. Multiple: Ctrl + click.",
        "organization_frame": " How to organize? ",
        "merge_update": "Join game and update",
        "merge_help": "Same folder. DLCs are separated into addcont.",
        "extract_here": "Extract into the program folder",
        "extract_here_help": "Ignores the output above and does not create a game subfolder.",
        "after_frame": " After extraction ",
        "delete_pkg": "Delete .pkg files after successful extraction",
        "delete_help": "Removes the originals. Unchecked = keep.",
        "extract": "🚀 Extract and Organize",
        "extract_selected": "Extract selected packages",
        "cancel": "⏹ Cancel",
        "cpu": "CPU:",
        "waiting": "Waiting for .pkg files...",
        "list_cleared": "List cleared. Drag new .pkg files here.",
        "wait_current_operation": "Wait for the current operation to finish before adding files.",
        "scanning": "Searching and analyzing packages...",
        "searching_from": "Searching for .pkg files in all folders and subfolders from: {path}...",
        "queue_status": "{count} package(s) queued. Click 'Extract and Organize'.",
        "no_packages": "No .pkg files found.",
        "file_not_found": "file not found",
        "choose_files_title": "Choose one or more .pkg files",
        "pkg_files": "PS4 .pkg files",
        "all_files": "All files",
        "choose_folder_title": "Choose a folder containing .pkg files",
        "choose_output_title": "Choose the output folder",
        "choose_package_title": "Choose the package",
        "choose_package_message": "Select the desired packages in the list, then click 'Extract selected packages'.",
        "error": "Error",
        "choose_output_message": "Choose a valid output folder.",
        "invalid_destination": "Invalid destination",
        "different_games": "Different games need separate folders. Uncheck 'Extract into the program folder'.",
        "cancel_requested": "Cancellation requested. Please wait...",
        "added": "Added {count} .pkg file(s) for extraction.",
        "no_compatible": "No compatible .pkg files found in this search.",
        "duplicate_warning": "Warning: '{filename}' is already in the list. Skipping duplicate.",
        "read_pkg_error": "Could not read '{filename}': {error}",
        "compare_pkg_error": "Could not compare '{filename}': {error}",
        "duplicate_ignored": "Duplicate file ignored: '{filename}' is identical to '{other}'.",
        "scan_cancelled": "Search cancelled. Packages already analyzed were kept.",
        "scan_failed": "Could not complete the search: {error}",
        "analyze_failed": "Error analyzing packages: {error}",
        "no_extractable": "No compatible package available for extraction.",
        "ignored_official": "Ignored (official)",
        "official_warning": "Warning: '{filename}' is an official Sony package with factory encryption. Ignored to prevent a lockup.",
        "start_extraction": "Starting extraction of {count} file(s).",
        "mode_here": "Mode: Extract here (no game subfolder)",
        "mode_subfolder": "Mode: .GameName subfolder based on the base game title",
        "destination_log": "Output folder: {path}",
        "missing_source": "Warning: '{filename}' is no longer in the source folder. Skipping this package.",
        "base_missing": "Warning: base game title is not available in the list; using the CUSA code as the folder.",
        "extraction_folder": "Extraction folder: {path}",
        "package_changed": "the package changed since it was added to the list; remove and add the file again",
        "completed_log": "✓ Completed successfully at: {path}",
        "file_deleted": ".pkg file deleted successfully: {filename}",
        "file_delete_failed": "Warning: Could not delete '{filename}': {error}",
        "none_available_log": "No package available for extraction. Add the files again.",
        "cancel_log": "\n⏹ Process cancelled by the user.",
        "error_log": "\n❌ EXTRACTION ERROR: {error}",
        "extract_error_title": "Extraction Error",
        "extract_error_message": "An error occurred:\n{error}",
        "preparing": "[{index}/{total}] Preparing: {filename}...",
        "extracting": "[{index}/{total}] Extracting: {filename} (0.0%)",
        "progress": "[{index}/{total}] {filename}: {percent:.1f}% ({done:.1f} MB of {total_mb:.1f} MB)",
        "completed_file": "[{index}/{total}] Completed: {filename}",
        "success": "Extraction completed successfully!",
        "partial_success": "Extraction finished: {completed}/{total} packages extracted. Check the warnings in the activity history.",
        "selected_success_log": "\nSelected packages extracted successfully.",
        "all_success_log": "\nAll files were extracted and organized.",
        "launcher_help": "The files were extracted and organized for easy Launcher use.",
        "selected_success": "The selected packages were fully extracted.",
        "all_success": "Extraction and organization completed successfully!\n\nThe files were extracted and organized for easy Launcher use.",
        "cancelled": "Extraction cancelled.",
        "missing_file": "File missing",
        "extracting_status": "Extracting...",
        "completed_status": "Completed",
        "cancelled_status": "Cancelled",
        "error_status": "Error",
        "ready_status": "Ready to extract",
        "official_status": "Official encryption",
        "base_type": "Base Game",
        "update_type": "Update",
        "dlc_type": "DLC / Extra",
        "other_type": "Other package",
    },
}


_RUNTIME_TRANSLATIONS = {
    "Conferindo a identificação completa do pacote...": "Checking the package identity...",
    "Registro anterior inválido; os arquivos existentes serão conferidos pelo pacote.": "Previous record is invalid; existing files will be checked against the package.",
    "Não foi possível ler o registro anterior; os arquivos existentes serão conferidos pelo pacote.": "Could not read the previous record; existing files will be checked against the package.",
    "O registro atingiu o limite de tamanho; os arquivos sem registro serão conferidos pelo pacote.": "The record reached its size limit; files without a record will be checked against the package.",
    "Não foi possível salvar o registro; os arquivos continuam válidos e serão conferidos na próxima tentativa.": "Could not save the record; files remain valid and will be checked on the next attempt.",
    "chave interna dk3 desbloqueada": "Internal dk3 key unlocked",
    "complemento sem imagem interna: extraindo licença e informações do pacote": "Add-on without an internal image: extracting license and package information",
    "chave do sistema de arquivos (ekpfs) desbloqueada": "File-system key (ekpfs) unlocked",
    "chaves de descriptografia geradas": "Decryption keys generated",
    "área de dados interna localizada": "Internal data area found",
    "complemento composto por licença e metadados; não precisa de área compactada": "Add-on contains only license and metadata; no compressed area is needed",
    "sistema de arquivos lido": "File system read",
    "extração concluída": "Extraction completed",
    "o pacote foi alterado durante a extração": "The package was changed during extraction",
    "o pacote foi alterado desde a leitura de suas informações": "The package was changed since its information was read",
    "o pacote foi alterado durante a análise": "The package was changed during analysis",
    "o pacote foi alterado desde que entrou na lista": "The package was changed since it was added to the list",
    "arquivo alterado durante a conferência": "File changed during verification",
    "arquivo alterado durante a extração": "File changed during extraction",
    "arquivo alterado durante a gravação": "File changed while writing",
    "arquivo extraído incompleto": "Extracted file is incomplete",
    "tamanho inválido no arquivo": "Invalid file size",
    "arquivo fora dos limites": "File is outside the valid limits",
    "caminho interno inválido": "Invalid internal path",
    "caminho de saída fora da pasta escolhida": "Output path is outside the selected folder",
    "não é um .pkg de PS4": "This is not a PS4 .pkg file",
    "tamanho no cabeçalho maior que o arquivo real": "Header size is larger than the actual file",
    "imagem interna fora dos limites do pacote": "Internal image is outside the package limits",
    "código do jogo inválido": "Invalid game code",
    "cabeçalho de imagem interna inconsistente": "Inconsistent internal image header",
    "jogo ou atualização sem imagem de arquivos interna": "Game or update has no internal file image",
    "não achei a tabela de chaves": "Key table not found",
    "image_key não encontrada no .pkg": "image_key not found in the .pkg",
    "tabela de arquivos fora dos limites do pacote": "File table is outside the package limits",
    "tabela de arquivos interna incompleta": "Internal file table is incomplete",
    "mapa PFSC inválido": "Invalid PFSC map",
    "área compactada (PFSC) não encontrada": "Compressed area (PFSC) not found",
    "bloco compactado inválido": "Invalid compressed block",
    "bloco compactado incompleto ou com tamanho inválido": "Incomplete or invalid-sized compressed block",
    "falta o componente de criptografia (pycryptodome)": "The encryption component (pycryptodome) is missing",
}


_RUNTIME_PREFIX_TRANSLATIONS = (
    ("Conferindo: ", "Checking: "),
    ("Extraindo: ", "Extracting: "),
    ("Reaproveitado: ", "Reused: "),
    ("Extraindo novamente: ", "Extracting again: "),
    ("mapa de arquivos: ", "File map: "),
    ("sistema de arquivos lido: ", "File system read: "),
    ("extração concluída: ", "Extraction completed: "),
    ("arquivo alterado durante a conferência: ", "File changed during verification: "),
    ("arquivo alterado durante a extração: ", "File changed during extraction: "),
    ("arquivo alterado durante a gravação: ", "File changed while writing: "),
    ("tamanho inválido no arquivo ", "Invalid file size in "),
)


def _parse_sfo(sfo_data):
    info = {}
    if sfo_data and sfo_data[:4] == b"\x00PSF":
        if len(sfo_data) < 20:
            raise ValueError("cabeçalho param.sfo incompleto")
        koff, doff, count = struct.unpack_from("<3I", sfo_data, 8)
        if 20 + count * 16 > koff or not koff <= doff <= len(sfo_data):
            raise ValueError("tabela param.sfo inválida")
        for i in range(count):
            k_o, fmt, plen, _, d_o = struct.unpack_from("<2H3I", sfo_data, 20 + i * 16)
            key_end = sfo_data.find(b"\0", koff + k_o, doff)
            if key_end < 0 or doff + d_o + plen > len(sfo_data):
                raise ValueError("campo param.sfo incompleto")
            key = sfo_data[koff + k_o:key_end].decode("utf-8", "replace")
            value = sfo_data[doff + d_o:doff + d_o + plen]
            if fmt == 0x0204:
                info[key] = value.rstrip(b"\x00").decode("utf-8", "replace")
            elif fmt == 0x0404:
                if len(value) != 4:
                    raise ValueError("campo numérico param.sfo inválido")
                info[key] = struct.unpack("<I", value)[0]
    return info


class Cancelled(Exception):
    pass


class PkgExtractor:
    def __init__(self, pkg_path, out_dir, protected_paths=()):
        self.path = Path(pkg_path).resolve()
        self.protected_paths = {self.path, *(Path(path).resolve() for path in protected_paths)}
        self.extract_dir = Path(out_dir).resolve()
        self.cancelled = False
        self.ecb_tweak = None
        self.ecb_data = None
        self.metadata_only = False

    def cancel(self):
        self.cancelled = True

    def _check(self):
        if self.cancelled:
            raise Cancelled()

    @contextmanager
    def _output_file(self, dest):
        dest = _safe_join(self.extract_dir, Path(dest).relative_to(self.extract_dir))
        if dest in self.protected_paths:
            raise ValueError("a saída não pode substituir um pacote de origem")
        dest.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", dir=dest.parent,
                                             prefix=".pkg-", suffix=".tmp", delete=False) as out:
                temporary = Path(out.name)
                yield out
            self._check()
            if hasattr(self, "_source_stamp") and _file_stamp(self.path) != self._source_stamp:
                raise ValueError("o pacote foi alterado durante a extração")
            os.replace(temporary, dest)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _file_digest(self, path):
        before = _file_stamp(path)
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            while True:
                self._check()
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        if _file_stamp(path) != before:
            raise ValueError("arquivo alterado durante a conferência: %s" % Path(path).name)
        return digest.hexdigest()

    def _prepare_resume(self, log):
        log("Conferindo a identificação completa do pacote...")
        self._source_stamp = _file_stamp(self.path)
        if getattr(self, "_parsed_stamp", self._source_stamp) != self._source_stamp:
            raise ValueError("o pacote foi alterado desde a leitura de suas informações")
        self._package_digest = self._file_digest(self.path)
        self._resume_files = {}
        self._resume_dirty = False
        self._resume_saved_at = None
        self._resume_path = _safe_join(self.extract_dir, RESUME_DIRECTORY,
                                       self._package_digest + ".json")
        if self._resume_path in self.protected_paths:
            raise ValueError("o registro da extração não pode substituir um pacote de origem")
        try:
            with open(self._resume_path, "rb") as stream:
                raw = stream.read(MAX_RESUME_BYTES + 1)
            state = json.loads(raw) if len(raw) <= MAX_RESUME_BYTES else None
            if (isinstance(state, dict) and state.get("version") == 1
                    and state.get("package_sha256") == self._package_digest
                    and isinstance(state.get("files"), dict)):
                self._resume_files = state["files"]
            else:
                log("Registro anterior inválido; os arquivos existentes serão conferidos pelo pacote.")
        except FileNotFoundError:
            pass
        except (OSError, ValueError, UnicodeError, RecursionError):
            log("Não foi possível ler o registro anterior; os arquivos existentes serão conferidos pelo pacote.")

    def _save_resume(self, log, force=False):
        if self._resume_path is None or not self._resume_dirty:
            return
        now = time.monotonic()
        if not force and self._resume_saved_at is not None and now - self._resume_saved_at < 1:
            return
        state = {"version": 1, "package_sha256": self._package_digest,
                 "files": self._resume_files}
        payload = json.dumps(state, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self._check()
        if len(payload) > MAX_RESUME_BYTES:
            log("O registro atingiu o limite de tamanho; os arquivos sem registro serão conferidos pelo pacote.")
            self._resume_path = None
            return
        try:
            with self._output_file(self._resume_path) as stream:
                stream.write(payload)
            self._resume_saved_at = time.monotonic()
            self._resume_dirty = False
        except OSError:
            log("Não foi possível salvar o registro; os arquivos continuam válidos e serão conferidos na próxima tentativa.")
            self._resume_path = None

    def _extract_or_reuse(self, dest, size, chunks, log, progress):
        self._check()
        if size < 0:
            raise ValueError("tamanho inválido no arquivo %s" % dest.name)
        key = dest.relative_to(self.extract_dir).as_posix().casefold()
        record = self._resume_files.get(key)
        digest = None
        existing = dest.is_file() and dest.stat().st_size == size
        log("Conferindo: %s" % dest.relative_to(self.extract_dir) if dest.exists()
            else "Extraindo: %s" % dest.relative_to(self.extract_dir))
        if existing:
            before = _file_stamp(dest)
            if (isinstance(record, dict) and record.get("size") == size
                    and isinstance(record.get("sha256"), str) and len(record["sha256"]) == 64):
                actual = self._file_digest(dest)
                if actual == record["sha256"]:
                    digest = actual
            else:
                candidate, compared = hashlib.sha256(), 0
                with open(dest, "rb") as previous:
                    for data in chunks():
                        self._check()
                        if previous.read(len(data)) != data:
                            break
                        candidate.update(data)
                        compared += len(data)
                    else:
                        if compared == size and not previous.read(1):
                            digest = candidate.hexdigest()
            if _file_stamp(dest) != before:
                raise ValueError("arquivo alterado durante a conferência: %s" % dest.name)
        if digest is not None:
            verified = before
            log("Reaproveitado: %s" % dest.relative_to(self.extract_dir))
            self.reused_files += 1
            if progress:
                progress(size)
        else:
            if dest.exists():
                log("Extraindo novamente: %s" % dest.relative_to(self.extract_dir))
            written, result = 0, hashlib.sha256()
            with self._output_file(dest) as out:
                for data in chunks():
                    self._check()
                    written += out.write(data)
                    result.update(data)
                    if progress:
                        progress(len(data))
                if written != size:
                    raise ValueError("arquivo extraído incompleto: %s (%d de %d bytes)"
                                     % (dest.name, written, size))
                out.flush()
                info = os.fstat(out.fileno())
                written_stamp = (info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino)
            digest = result.hexdigest()
            verified = _file_stamp(dest)
            if (verified[0], verified[1], verified[3], verified[4]) != written_stamp:
                raise ValueError("arquivo alterado durante a gravação: %s" % dest.name)
        self._check()
        if _file_stamp(self.path) != self._source_stamp:
            raise ValueError("o pacote foi alterado durante a extração")
        if _file_stamp(dest) != verified:
            raise ValueError("arquivo alterado durante a conferência: %s" % dest.name)
        self._verified_stamps[dest] = verified
        completed = {"size": size, "sha256": digest}
        if record != completed:
            self._resume_files[key] = completed
            self._resume_dirty = True
        self._save_resume(log)

    def _metadata_chunks(self, index, entry, stream):
        ident, _name_off, _flag1, _flag2, offset, size = entry
        if ident in (0x400, 0x401, 0x402, 0x403):
            remaining = ((size + 15) // 16) * 16
            ivkey = hashlib.sha256(self.entry_raw[index] + self.dk3).digest()
            cipher = AES.new(ivkey[16:32], AES.MODE_CBC, ivkey[:16])
        else:
            remaining, cipher = size, None
        stream.seek(offset)
        decoded = 0
        while remaining:
            self._check()
            raw = _read_exact(stream, min(1024 * 1024, remaining), "entrada de metadados truncada")
            remaining -= len(raw)
            data = cipher.decrypt(raw) if cipher else raw
            data = data[:size - decoded]
            decoded += len(data)
            yield data

    def _pfs_chunks(self, size, loc, nblocks, stream):
        decoded = 0
        for index in range(loc, loc + nblocks):
            self._check()
            if decoded == size:
                break
            start = self.sector_map[index]
            stored = self.sector_map[index + 1] - start
            if stored <= 0:
                continue
            piece = self._read_pfsc_block(start, min(stored, SBLOCK), stream)
            data = self._decompress_block(piece)[:size - decoded]
            decoded += len(data)
            yield data

    def parse_pkg(self, log):
        p = self.path
        self._check()
        self._parsed_stamp = _file_stamp(p)
        self.metadata_only = False
        if AES is None:
            raise ValueError("falta o componente de criptografia (pycryptodome)")
        file_size = p.stat().st_size
        with open(p, "rb") as f:
            hdr = f.read(0x1000)
            if len(hdr) < 0x1000:
                raise ValueError("arquivo pequeno demais para ser um .pkg")
            (magic, _pkg_type, _u8, _file_count, table_count,
             _sc_count, _tab2, table_offset, _sc_size, _body_off, _body_size,
             _c_off, _c_size) = struct.unpack_from(">5I2H2I4Q", hdr, 0)
            if magic != MAGIC_PKG:
                raise ValueError("não é um .pkg de PS4 (assinatura diferente)")

            (self.pfs_image_offset, self.pfs_image_size, _m_off, _m_s,
             pkg_size) = struct.unpack_from(">QQQQQ", hdr, 0x410)
            (_pfs_signed_size, self.pfs_cache_size) = struct.unpack_from(">II", hdr, 0x438)
            if pkg_size > file_size:
                raise ValueError("tamanho no cabeçalho maior que o arquivo real")
            if self.pfs_image_offset + self.pfs_image_size > file_size:
                raise ValueError("imagem interna fora dos limites do pacote")
            self.entries = []
            self.entry_raw = {}
            for entry, raw in _read_pkg_entries(f, table_offset, table_count, file_size, self._check):
                if entry[0] in (0x20, 0x400, 0x401, 0x402, 0x403):
                    self.entry_raw[len(self.entries)] = raw
                self.entries.append(entry)

            sfo_entry = next((entry for entry in self.entries if entry[0] == 0x1000), None)
            sfo = {}
            if sfo_entry is not None:
                f.seek(sfo_entry[4])
                sfo = _parse_sfo(_read_exact(f, sfo_entry[5], "param.sfo incompleto", self._check))
            content_id = hdr[0x40:0x64].decode("latin-1", "replace").rstrip("\x00")
            self.title_id = sfo.get("TITLE_ID") or content_id[7:16]
            if not isinstance(self.title_id, str):
                raise ValueError("código do jogo inválido no pacote")

            if self.pfs_image_size == 0:
                if self.pfs_image_offset or self.pfs_cache_size:
                    raise ValueError("cabeçalho de imagem interna inconsistente")
                if sfo_entry is None:
                    raise ValueError("pacote sem imagem interna e sem param.sfo")
                if sfo.get("CATEGORY") != "ac":
                    raise ValueError("jogo ou atualização sem imagem de arquivos interna")
                self.metadata_only = True

            dk3 = None
            imgkeydata = None
            entry20_idx = None
            for idx_e, (ident, name_off, flag1, flag2, off, sz) in enumerate(self.entries):
                self._check()
                if ident == 0x10:
                    if sz < 32 + 224 + 4 * 256:
                        raise ValueError("entry_keys incompleta")
                    f.seek(off + 32 + 224 + 3 * 256)
                    dk3 = _rsa_decrypt(KEYSET_DK3, _read_exact(f, 256, "entry_keys incompleta"))
                    log("chave interna dk3 desbloqueada")
                elif ident == 0x20 and not self.metadata_only:
                    entry20_idx = idx_e
                    f.seek(off)
                    imgkeydata = f.read(256)
                    if len(imgkeydata) != 256:
                        raise ValueError("image_key incompleta")

            if dk3 is None:
                raise ValueError("não achei a tabela de chaves (não parece fake PKG 5.05+)")
            self.dk3 = dk3
            if self.metadata_only:
                log("complemento sem imagem interna: extraindo licença e informações do pacote")
                return self
            if imgkeydata is None or entry20_idx is None:
                raise ValueError("image_key não encontrada no .pkg")

            entry32 = self.entry_raw[entry20_idx]
            ivkey = hashlib.sha256(entry32 + dk3).digest()
            imgkey = AES.new(ivkey[16:32], AES.MODE_CBC, ivkey[:16]).decrypt(imgkeydata)
            ekpfs = _rsa_decrypt(KEYSET_FAKE, imgkey)
            log("chave do sistema de arquivos (ekpfs) desbloqueada")

            f.seek(self.pfs_image_offset + 0x370)
            seed = _read_exact(f, 16, "semente de criptografia incompleta")

        digest = hmac.new(ekpfs, struct.pack("<I", 1) + seed, hashlib.sha256).digest()
        self.ecb_tweak = AES.new(digest[:16], AES.MODE_ECB)
        self.ecb_data = AES.new(digest[16:], AES.MODE_ECB)
        log("chaves de descriptografia geradas")
        return self

    def _xts_decrypt(self, raw, sector_start):
        if len(raw) % 16:
            raise ValueError("trecho XTS não é múltiplo de 16")
        if not raw:
            return b""
        sectors = (len(raw) + BLOCK - 1) // BLOCK
        tweaks = self.ecb_tweak.encrypt(b"".join(
            struct.pack("<Q", sector_start + i) + b"\0" * 8 for i in range(sectors)))
        tables = _xts_mask_tables()
        masks = []
        for i in range(sectors):
            self._check()
            value = int.from_bytes(tweaks[i * 16:(i + 1) * 16], "little")
            mask = 0
            for table in tables:
                mask ^= table[value & 63]
                value >>= 6
            masks.append(mask.to_bytes(BLOCK, "little"))
        mask = b"".join(masks)[:len(raw)]
        return strxor(self.ecb_data.decrypt(strxor(raw, mask)), mask)

    def _pfsc_header(self, log):
        p = self.path
        length = self.pfs_cache_size * 2
        if length == 0 or length > self.pfs_image_size:
            length = self.pfs_image_size
        pfsc_off = -1
        pos = 0x20000
        with open(p, "rb") as f:
            while pos < length and pfsc_off < 0:
                self._check()
                chunk = min(BLOCK * 256, length - pos)
                f.seek(self.pfs_image_offset + pos)
                enc = _read_exact(f, chunk, "dados PFSC truncados")
                buf = self._xts_decrypt(enc, pos // BLOCK)
                for off in range(0, len(buf) - 47, SBLOCK):
                    if struct.unpack_from("<I", buf, off)[0] == MAGIC_PFSC:
                        pfsc_off = pos + off
                        break
                if pfsc_off >= 0:
                    break
                pos += chunk
            if pfsc_off < 0:
                raise ValueError("área compactada (PFSC) não encontrada — este .pkg pode não ser fake PKG 5.05+")
            log("área de dados interna localizada (PFSC em 0x%X)" % pfsc_off)
            (magic, _u4, _u8, _b_sz, block_sz2, block_offsets,
             _d_start, data_length) = struct.unpack_from("<4I4q", buf, off)
            if block_sz2 != SBLOCK or data_length < 0 or block_offsets < 48:
                raise ValueError("cabeçalho PFSC inválido ou formato não suportado")
            num_blocks = data_length // block_sz2
            need = block_offsets + (num_blocks + 1) * 8
            need_al = ((need + BLOCK - 1) // BLOCK) * BLOCK
            if need_al > self.pfs_image_size - pfsc_off:
                raise ValueError("mapa PFSC fora dos limites da imagem")
            f.seek(self.pfs_image_offset + pfsc_off)
            enc = _read_exact(f, need_al, "mapa PFSC truncado")

        dec = self._xts_decrypt(enc, pfsc_off // BLOCK)
        self.pfsc_offset = pfsc_off
        self.num_blocks = num_blocks
        self.sector_map = array("Q")
        self.sector_map.frombytes(dec[block_offsets:need])
        if sys.byteorder != "little":
            self.sector_map.byteswap()
        if (any(a > b or b - a > SBLOCK for a, b in pairwise(self.sector_map))
                or self.sector_map[-1] > self.pfs_image_size - pfsc_off):
            raise ValueError("mapa PFSC inválido")
        log("mapa de arquivos: %d blocos de 64 KiB" % num_blocks)
        return num_blocks

    def _read_pfsc_block(self, so, ssize, f_in):
        abs_pfs = self.pfsc_offset + so
        sec0 = abs_pfs // BLOCK
        start = sec0 * BLOCK
        need = (abs_pfs % BLOCK) + ssize
        rd = ((need + BLOCK - 1) // BLOCK) * BLOCK
        rd = min(rd, self.pfs_image_size - start)
        if rd % 16:
            rd -= rd % 16
        if so < 0 or ssize <= 0 or rd < need:
            raise ValueError("bloco PFSC fora dos limites da imagem")
        f_in.seek(self.pfs_image_offset + start)
        raw = _read_exact(f_in, rd, "bloco PFSC truncado")
        dec = self._xts_decrypt(raw, sec0)
        return dec[abs_pfs - start:abs_pfs - start + ssize]

    @staticmethod
    def _decompress_block(raw):
        if len(raw) == SBLOCK:
            return raw
        decoder = zlib.decompressobj()
        try:
            got = decoder.decompress(raw, SBLOCK + 1)
        except zlib.error as error:
            raise ValueError("bloco compactado inválido") from error
        if not decoder.eof or len(got) > SBLOCK or decoder.unused_data:
            raise ValueError("bloco compactado incompleto ou com tamanho inválido")
        return got.ljust(SBLOCK, b"\0")

    def scan_fs(self, log):
        self._check()
        metadata_total = sum(
            sz for ident, _name_off, _flag1, _flag2, _off, sz in self.entries
            if ident in ENTRY_NAMES and ident not in META_SKIP
        )
        if self.metadata_only:
            self.inodes = []
            self.dirs = set()
            self.files = []
            self.sector_map = array("Q")
            self.num_blocks = 0
            self.output_total = metadata_total
            log("complemento composto por licença e metadados; não precisa de área compactada")
            return self
        self._pfsc_header(log)
        sm = self.sector_map
        ndinode = 0
        inodes = []
        uroot_reached = False
        dinode_reached = False
        flat_paths_found = False
        end_reached = False
        counter = 0
        dirs = set()
        files = []
        extract_paths = {}
        game_dir = self.extract_dir
        current_dir = game_dir
        occupied = 0
        with open(self.path, "rb") as f_in:
            for i in range(self.num_blocks):
                self._check()
                so = sm[i]
                ssize = sm[i + 1] - so
                if ssize <= 0:
                    continue
                if ssize > SBLOCK:
                    ssize = SBLOCK
                piece = self._read_pfsc_block(so, ssize, f_in)
                block = self._decompress_block(piece)
                if i == 0:
                    ndinode = struct.unpack_from("<I", block, 0x30)[0]
                    if not 0 < ndinode <= (self.num_blocks - 1) * (SBLOCK // 0xA8):
                        raise ValueError("tabela de arquivos interna incompleta")
                    occupied = (ndinode * 0xA8 + SBLOCK - 1) // SBLOCK
                if 1 <= i <= occupied:
                    for off in range(0, SBLOCK - 0xA8 + 1, 0xA8):
                        mode = struct.unpack_from("<H", block, off)[0]
                        if mode == 0:
                            break
                        size = struct.unpack_from("<q", block, off + 8)[0]
                        blocks, loc = struct.unpack_from("<II", block, off + 96)
                        inodes.append((size, loc, blocks))
                b = block
                if b[0x10:0x1F] == b"flat_path_table":
                    flat_paths_found = True
                    uroot_reached = True
                if uroot_reached:
                    j = 0
                    while True:
                        if j + 16 > SBLOCK:
                            break
                        ino, dtype, namelen, entsize = struct.unpack_from("<4i", b, j)
                        if ino == 0:
                            extract_paths[counter] = game_dir
                            uroot_reached = False
                            break
                        if entsize <= 0:
                            break
                        counter += 1
                        j += entsize
                if b[0x10:0x11] == b"." and b[0x28:0x2A] == b"..":
                    dinode_reached = True
                if dinode_reached:
                    end_reached = False
                    j = 0
                    while j + 16 <= SBLOCK:
                        ino, dtype, namelen, entsize = struct.unpack_from("<4i", b, j)
                        if ino == 0 or entsize <= 0:
                            break
                        if namelen < 0 or entsize < 16 + namelen or j + entsize > SBLOCK:
                            raise ValueError("entrada de pasta inválida")
                        name = b[j + 16:j + 16 + namelen].decode("utf-8", "strict")
                        if dtype == PFS_CURRENT_DIR:
                            current_dir = extract_paths.get(ino, game_dir)
                        elif dtype == PFS_PARENT_DIR:
                            pass
                        else:
                            extract_paths[ino] = _safe_join(current_dir, name)
                            if dtype == PFS_DIR:
                                dirs.add(str(extract_paths[ino]))
                        if dtype in (PFS_FILE, PFS_DIR):
                            if dtype == PFS_FILE:
                                files.append((extract_paths[ino].relative_to(game_dir).as_posix(), ino))
                            counter += 1
                            if counter + 1 == ndinode:
                                end_reached = True
                        j += entsize
                    if end_reached:
                        break
        if (not flat_paths_found or uroot_reached or not dinode_reached or not end_reached
                or len(inodes) < ndinode
                or any(ino < 0 or ino >= len(inodes) for _name, ino in files)):
            raise ValueError("tabela de arquivos interna incompleta")
        self.inodes = inodes
        self.dirs = dirs
        self.files = files
        pfs_total = sum(max(0, inodes[ino][0]) for _fname, ino in files)
        self.output_total = metadata_total + pfs_total
        log("sistema de arquivos lido: %d pastas e %d arquivos do jogo" % (len(dirs), len(files)))
        return self

    def extract(self, log, progress=None):
        self._check()
        directory_paths = [_safe_join(self.extract_dir, Path(directory).relative_to(self.extract_dir))
                           for directory in self.dirs]
        metadata_paths = {index: _safe_join(self.extract_dir, "sce_sys", ENTRY_NAMES[entry[0]])
                          for index, entry in enumerate(self.entries)
                          if entry[0] in ENTRY_NAMES and entry[0] not in META_SKIP}
        file_paths = [_safe_join(self.extract_dir, name) for name, _ino in self.files]
        seen = set()
        for paths in (metadata_paths.values(), file_paths):
            for dest in paths:
                self._check()
                if dest in self.protected_paths:
                    raise ValueError("a saída não pode substituir um pacote de origem")
                if dest.relative_to(self.extract_dir).parts[0].casefold() == RESUME_DIRECTORY:
                    raise ValueError("o pacote usa a pasta reservada ao registro da extração")
                key = str(dest).casefold()
                if key in seen:
                    raise ValueError("o pacote contém arquivos com o mesmo destino: %s" % dest.name)
                seen.add(key)
        self.extract_dir.mkdir(parents=True, exist_ok=True)
        self.reused_files = 0
        self._verified_stamps = {}
        self._prepare_resume(log)
        created = 0
        with open(self.path, "rb") as f:
            for j0, entry in sorted(
                    enumerate(self.entries), key=lambda entry: entry[1][0] != 0x1000):
                self._check()
                ident, _name_off, _flag1, _flag2, _off, sz = entry
                if ident not in ENTRY_NAMES or ident in META_SKIP:
                    continue
                dest = metadata_paths[j0]
                self._extract_or_reuse(dest, sz, lambda: self._metadata_chunks(j0, entry, f),
                                       log, progress)
                created += 1

        for directory in sorted(directory_paths):
            self._check()
            _safe_join(self.extract_dir, directory.relative_to(self.extract_dir)).mkdir(parents=True, exist_ok=True)

        sm = self.sector_map
        inodes = self.inodes
        with open(self.path, "rb") as f_pkg:
            for (fname, ino), dest in zip(self.files, file_paths):
                self._check()
                size, loc, nblocks = inodes[ino]
                if size < 0:
                    raise ValueError("tamanho inválido no arquivo %s" % fname)
                if loc < 0 or nblocks < 0 or loc + nblocks >= len(sm):
                    raise ValueError("arquivo %s: blocos fora do mapa" % fname)
                self._extract_or_reuse(dest, size, lambda: self._pfs_chunks(size, loc, nblocks, f_pkg),
                                       log, progress)
                created += 1
        self._save_resume(log, force=True)
        for dest, stamp in self._verified_stamps.items():
            self._check()
            if _file_stamp(dest) != stamp:
                raise ValueError("arquivo alterado durante a extração: %s" % dest.name)
        if _file_stamp(self.path) != self._source_stamp:
            raise ValueError("o pacote foi alterado durante a extração")
        log("%d arquivo(s) reaproveitado(s); %d arquivo(s) extraído(s) novamente ou criado(s)."
            % (self.reused_files, created - self.reused_files))
        log("extração concluída: %d arquivos no total" % created)
        return created


def compute_pkg_fingerprint(pkg_path, check=lambda: None):
    p = Path(pkg_path)
    size = p.stat().st_size
    with open(p, "rb") as f:
        hdr = f.read(0x1000)
        hdr_digest = hdr[0x100:0x120].hex() if len(hdr) >= 0x120 else ""
        if size < 50 * 1024 * 1024:
            h = hashlib.sha256()
            f.seek(0)
            while chunk := f.read(1024 * 1024):
                check()
                h.update(chunk)
            return h.hexdigest()
        else:
            h = hashlib.sha256()
            h.update(f"{size}:{hdr_digest}:".encode())
            f.seek(0)
            h.update(f.read(1024 * 1024))
            f.seek(max(0, size - 1024 * 1024))
            h.update(f.read(1024 * 1024))
            return h.hexdigest()


def _same_pkg_content(first, second, check=lambda: None):
    if Path(first).stat().st_size != Path(second).stat().st_size:
        return False
    with open(first, "rb") as left, open(second, "rb") as right:
        while True:
            check()
            chunk = left.read(1024 * 1024)
            if chunk != right.read(1024 * 1024):
                return False
            if not chunk:
                return True


def _game_folder_names(items):
    folders = {}
    for item in sorted(items, key=_pkg_sort_key):
        if item.get("kind") != "base" or not item.get("title_id") or not item.get("title"):
            continue
        title = item["title"].replace("™", "").replace("®", "")
        title = "".join("_" if ord(char) < 32 or char in '<>:"/\\|?*' else char for char in title)
        title = " ".join(title.split()).strip(" .")[:200].rstrip(" .")
        if title:
            folders.setdefault(item["title_id"], "." + title)
    same_names = {}
    for tid, name in folders.items():
        same_names.setdefault(name.casefold(), []).append(tid)
    for tids in same_names.values():
        if len(tids) > 1:
            for tid in tids:
                folders[tid] += "-" + tid
    used = set()
    for tid in sorted(folders):
        original = folders[tid]
        candidate = original
        number = 0
        while candidate.casefold() in used:
            candidate = original + "-" + tid + (f"-{number}" if number else "")
            number += 1
        folders[tid] = candidate
        used.add(candidate.casefold())
    return folders


def _check_game_identity(directory, title_id, strict=True):
    sfo = _safe_join(directory, "sce_sys", "param.sfo")
    if sfo.is_file():
        existing_id = _parse_sfo(sfo.read_bytes()).get("TITLE_ID")
        if existing_id != title_id:
            raise ValueError("a pasta de destino pertence a outro jogo ou não pôde ser identificada; escolha outra pasta")
        return
    if strict and Path(directory).is_dir():
        for child in Path(directory).iterdir():
            if child.name == "sce_sys" and child.is_dir() and not any(child.iterdir()):
                continue
            if (child.name == "addcont" and child.is_dir()
                    and all(path.name == title_id and path.is_dir() for path in child.iterdir())):
                continue
            if child.is_dir() and child.name in (title_id, title_id + "-patch"):
                _check_game_identity(child, title_id, strict=False)
                continue
            raise ValueError("a pasta já contém arquivos sem identificação segura; escolha outra pasta")


def _target_directory(out_base, item, extract_here=False, merge_update=False, game_folders=None):
    out_base = Path(out_base).resolve()
    tid = item["title_id"]
    if not tid or len(PureWindowsPath(tid).parts) != 1:
        raise ValueError("código do jogo inválido")
    if game_folders is None:
        game_folders = _game_folder_names([item])
    folder = game_folders.get(tid)
    if folder:
        wrapper = _safe_join(out_base, folder)
        base = _safe_join(wrapper, tid)
    else:
        wrapper = None
        base = _safe_join(out_base, tid)
    _check_game_identity(out_base if extract_here else (wrapper or base), tid, strict=not extract_here)
    if wrapper and not extract_here:
        _check_game_identity(base, tid)
    if item["kind"] == "dlc":
        name = item.get("content_id", "DLC").split("-")[-1] or "EXTRA"
        if len(PureWindowsPath(name).parts) != 1:
            raise ValueError("código do complemento inválido")
        dlc_root = wrapper if wrapper and not extract_here else out_base
        target = _safe_join(dlc_root, "addcont", tid, name)
        _check_game_identity(target, tid)
        return target
    if item["kind"] == "update":
        if merge_update and (extract_here or base.is_dir() or folder):
            return out_base if extract_here else base
        patch_parent = wrapper or out_base
        target = _safe_join(patch_parent, tid + "-patch")
        _check_game_identity(target, tid)
        return target
    return out_base if extract_here else base


def inspect_pkg_quick(pkg_path, check=lambda: None):
    p = Path(pkg_path)
    if not p.is_file():
        return None
    try:
        check()
        source_stamp = _file_stamp(p)
        size = source_stamp[0]
        with open(p, "rb") as f:
            hdr = f.read(0x1000)
            if len(hdr) < 0x1000:
                return {"valid": False, "error": "Arquivo muito pequeno para ser .pkg", "filename": p.name, "path": p}
            magic, _pkg_type, _, _, table_count, _, _, table_offset = struct.unpack_from(">5I2HI", hdr, 0)
            if magic != MAGIC_PKG:
                return {"valid": False, "error": "Não é um arquivo .pkg de PS4", "filename": p.name, "path": p}
            content_id = hdr[0x40:0x64].decode("latin-1", "replace").rstrip("\x00")

            has_dk3 = False
            sfo_data = None
            for (ident, _, _, _, off, sz), _raw in _read_pkg_entries(f, table_offset, table_count, size, check):
                if ident == 0x10:
                    has_dk3 = True
                elif ident == 0x1000:
                    f.seek(off)
                    sfo_data = _read_exact(f, sz, "param.sfo incompleto", check)

        sfo_info = _parse_sfo(sfo_data)

        category = sfo_info.get("CATEGORY", "desconhecido")
        title_id = sfo_info.get("TITLE_ID", content_id[7:16] if len(content_id) >= 16 else "PS4GAME")
        title = sfo_info.get("TITLE", p.stem)
        app_ver = sfo_info.get("APP_VER", sfo_info.get("VERSION", "1.00"))

        kind = {"gd": "base", "gp": "update", "ac": "dlc"}.get(category, "other")

        if size >= 1024 * 1024 * 1024:
            size_str = f"{size / (1024 * 1024 * 1024):.2f} GB"
        else:
            size_str = f"{size / (1024 * 1024):.1f} MB"

        fingerprint = compute_pkg_fingerprint(p, check)
        if _file_stamp(p) != source_stamp:
            raise ValueError("o pacote foi alterado durante a análise; adicione o arquivo novamente")

        return {
            "valid": True,
            "path": p,
            "filename": p.name,
            "is_fake": has_dk3,
            "title": title,
            "title_id": title_id,
            "app_ver": app_ver,
            "category": category,
            "kind": kind,
            "content_id": content_id,
            "size": size,
            "size_str": size_str,
            "fingerprint": fingerprint,
            "source_stamp": source_stamp,
            "status": "Pronto para extrair" if has_dk3 else "Criptografia oficial",
            "error": None if has_dk3 else "Pacote oficial da Sony com criptografia de fábrica (sem chaves fake)"
        }
    except Cancelled:
        raise
    except Exception as e:
        return {"valid": False, "error": str(e), "filename": p.name, "path": p}


def setup_drag_and_drop(root, on_drop):
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        shell32 = ctypes.windll.shell32

        WM_DROPFILES = 0x0233
        WM_COPYDATA = 0x004A
        WM_COPYGLOBALDATA = 0x0049
        MSGFLT_ADD = 1

        for msg_id in (WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA):
            try:
                user32.ChangeWindowMessageFilter(msg_id, MSGFLT_ADD)
            except Exception:
                pass

        LRESULT = ctypes.c_ssize_t
        WPARAM = wintypes.WPARAM
        LPARAM = wintypes.LPARAM
        HWND = wintypes.HWND
        UINT = wintypes.UINT
        GWL_WNDPROC = -4

        WNDPROC = ctypes.WINFUNCTYPE(LRESULT, HWND, UINT, WPARAM, LPARAM)
        user32.GetParent.argtypes = [HWND]
        user32.GetParent.restype = HWND
        user32.IsWindow.argtypes = [HWND]
        user32.IsWindow.restype = wintypes.BOOL
        user32.DefWindowProcW.argtypes = [HWND, UINT, WPARAM, LPARAM]
        user32.DefWindowProcW.restype = LRESULT
        user32.CallWindowProcW.argtypes = [ctypes.c_void_p, HWND, UINT, WPARAM, LPARAM]
        user32.CallWindowProcW.restype = LRESULT
        set_window_proc = (user32.SetWindowLongPtrW if ctypes.sizeof(ctypes.c_void_p) == 8
                           else user32.SetWindowLongW)
        set_window_proc.argtypes = [HWND, ctypes.c_int, ctypes.c_void_p]
        set_window_proc.restype = ctypes.c_void_p
        shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, UINT, wintypes.LPWSTR, UINT]
        shell32.DragQueryFileW.restype = UINT
        shell32.DragFinish.argtypes = [wintypes.HANDLE]
        shell32.DragFinish.restype = None
        shell32.DragAcceptFiles.argtypes = [HWND, wintypes.BOOL]
        shell32.DragAcceptFiles.restype = None

        root.update()
        root.update_idletasks()

        old_procs = {}
        root_ref = weakref.ref(root)
        drop_ref = weakref.WeakMethod(on_drop) if getattr(on_drop, "__self__", None) is not None else lambda: on_drop

        def custom_wndproc(h, msg, wp, lp):
            if msg == WM_DROPFILES:
                hdrop = wp
                count = shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0)
                dropped = []
                for i in range(count):
                    length = shell32.DragQueryFileW(hdrop, i, None, 0) + 1
                    buf = ctypes.create_unicode_buffer(length)
                    shell32.DragQueryFileW(hdrop, i, buf, length)
                    if buf.value:
                        dropped.append(buf.value)
                shell32.DragFinish(hdrop)
                target, callback = root_ref(), drop_ref()
                if dropped and target is not None and callback is not None:
                    target.after(0, callback, dropped)
                return 0
            old = old_procs.get(h)
            if old:
                return user32.CallWindowProcW(old, h, msg, wp, lp)
            return user32.DefWindowProcW(h, msg, wp, lp)

        c_proc = WNDPROC(custom_wndproc)
        root._wndproc_ref = c_proc

        def cleanup():
            for h, old in old_procs.items():
                if user32.IsWindow(h):
                    set_window_proc(h, GWL_WNDPROC, old)
            old_procs.clear()
            target = root_ref()
            if target is not None:
                target._wndproc_ref = None
                target._drop_cleanup = None

        root._drop_cleanup = cleanup

        all_hwnds = set()
        r_id = root.winfo_id()
        if r_id:
            all_hwnds.add(r_id)
        parent = user32.GetParent(r_id)
        if parent:
            all_hwnds.add(parent)

        def enum_cb(h, lp):
            all_hwnds.add(h)
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user32.EnumChildWindows.argtypes = [HWND, WNDENUMPROC, LPARAM]
        user32.EnumChildWindows.restype = wintypes.BOOL
        user32.EnumChildWindows(parent or r_id, WNDENUMPROC(enum_cb), 0)

        for h in all_hwnds:
            try:
                shell32.DragAcceptFiles(h, True)
                old = set_window_proc(h, GWL_WNDPROC, ctypes.cast(c_proc, ctypes.c_void_p))
                if old:
                    old_procs[h] = old
            except Exception:
                pass

        return True
    except Exception:
        return False


def _avisa_sem_crypto():
    if tk is None:
        return False
    try:
        r = tk.Tk()
    except tk.TclError:
        return False
    r.withdraw()
    messagebox.showerror(
        "Easy PKG Extractor",
        "Falta o componente de criptografia (pycryptodome).\n\n"
        "No Windows, abra o terminal e rode:\n"
        "    pip install pycryptodome\n\n"
        "Depois abra este programa de novo.")
    r.destroy()
    return True


try:
    import psutil
    psutil.cpu_percent(interval=None)
except Exception:
    psutil = None

_last_cpu_times = None


def get_cpu_percent():
    if psutil:
        try:
            return psutil.cpu_percent(interval=None)
        except Exception:
            pass
    global _last_cpu_times
    try:
        import ctypes
        from ctypes import wintypes

        def _to_i(ft):
            return (ft.dwHighDateTime << 32) | ft.dwLowDateTime

        idle, kernel, user = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
        if ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            i, k, u = _to_i(idle), _to_i(kernel), _to_i(user)
            if _last_cpu_times:
                last_i, last_k, last_u = _last_cpu_times
                d_idle = i - last_i
                d_total = (k - last_k) + (u - last_u)
                _last_cpu_times = (i, k, u)
                if d_total > 0:
                    pct = 100.0 * (1.0 - (d_idle / d_total))
                    return max(0.0, min(100.0, pct))
            _last_cpu_times = (i, k, u)
    except Exception:
        pass
    return 0.0


class App:
    def __init__(self, root, initial_files=None):
        self.root = root
        self.language = "en"
        self.ui = {}
        root.title(self._t("title"))
        root.geometry("820x620")
        root.minsize(740, 600)

        self.pkg_list = []
        self._next_tree_id = 1
        self.active_extractor = None
        self.is_extracting = False
        self.is_scanning = False
        self._scan_cancelled = threading.Event()
        self._events = queue.SimpleQueue()
        self._worker = None
        self.batch_cancelled = threading.Event()
        self.closing = False
        self.default_dest = str(_application_directory())
        root.protocol("WM_DELETE_WINDOW", self.close)

        self._build_ui()
        setup_drag_and_drop(root, self.add_pkgs)
        self.root.after(20, self._poll_events)

        if initial_files:
            self.add_pkgs(initial_files)
        else:
            self.root.after(100, self.scan_current_folder)

        self.root.after(500, self._update_cpu)

    def _t(self, key, **values):
        text = LANGUAGE_TEXT[self.language][key]
        return text.format(**values) if values else text

    def _translate_runtime(self, text):
        text = str(text)
        if self.language == "pt":
            return text
        if text in _RUNTIME_TRANSLATIONS:
            return _RUNTIME_TRANSLATIONS[text]
        for source, target in _RUNTIME_PREFIX_TRANSLATIONS:
            if text.startswith(source):
                return target + text[len(source):]
        for source, target in _RUNTIME_TRANSLATIONS.items():
            if source in text:
                text = text.replace(source, target)
        return text

    def _set_status(self, text):
        self.lbl_status.config(text=self._translate_runtime(text))

    def _status_text(self, status):
        status_keys = {
            "Pronto para extrair": "ready_status",
            "Criptografia oficial": "official_status",
            "Ignorado (oficial)": "ignored_official",
            "Arquivo ausente": "missing_file",
            "Extraindo...": "extracting_status",
            "Concluído": "completed_status",
            "Cancelado": "cancelled_status",
            "Erro": "error_status",
        }
        key = status_keys.get(status)
        return self._t(key) if key else self._translate_runtime(status)

    def _category_label(self, item):
        keys = {
            "base": "base_type",
            "update": "update_type",
            "dlc": "dlc_type",
        }
        return self._t(keys.get(item.get("kind"), "other_type"))

    def _build_ui(self):
        root = self.root

        language_bar = tk.Frame(root)
        language_bar.pack(fill="x", padx=10, pady=(2, 0))
        self.language_button = tk.Button(
            language_bar, text=self._t("language_button"), command=self.toggle_language,
            padx=6, pady=2)
        self.language_button.pack(side="left")

        drop_frame = tk.LabelFrame(root, text=self._t("add_files_frame"), font=("Segoe UI", 9, "bold"), padx=10, pady=8)
        drop_frame.pack(fill="x", padx=10, pady=6)
        self.ui["add_files_frame"] = drop_frame

        lbl_hint = tk.Label(
            drop_frame,
            text=self._t("hint"),
            font=("Segoe UI", 9),
            fg="#1565c0",
            justify="center"
        )
        lbl_hint.pack(fill="x", pady=4)
        self.ui["hint"] = lbl_hint

        btn_bar = tk.Frame(drop_frame)
        btn_bar.pack(fill="x", pady=4)

        self.btn_scan = tk.Button(btn_bar, text=self._t("scan_folder"), command=self.scan_current_folder, width=22)
        self.btn_scan.pack(side="left", padx=4)
        self.btn_add_files = tk.Button(btn_bar, text=self._t("add_files"), command=self.pick_files, width=20)
        self.btn_add_files.pack(side="left", padx=4)
        self.btn_add_folder = tk.Button(btn_bar, text=self._t("add_folder"), command=self.pick_folder, width=20)
        self.btn_add_folder.pack(side="left", padx=4)
        self.btn_clear = tk.Button(btn_bar, text=self._t("clear_list"), command=self.clear_list, width=14)
        self.btn_clear.pack(side="right", padx=4)
        self.ui.update({
            "scan_folder": self.btn_scan,
            "add_files": self.btn_add_files,
            "add_folder": self.btn_add_folder,
            "clear_list": self.btn_clear,
        })

        list_frame = tk.LabelFrame(root, text=self._t("detected_frame"), font=("Segoe UI", 9, "bold"), padx=6, pady=6)
        list_frame.pack(fill="both", expand=True, padx=10, pady=4)
        self.ui["detected_frame"] = list_frame

        self.package_columns = ("tipo", "nome", "id", "ver", "tam", "arquivo", "status")
        self.tree = ttk.Treeview(
            list_frame, columns=self.package_columns, show="headings", selectmode="extended", height=2)
        self.tree.configure(displaycolumns=("status", "tipo", "nome", "id", "ver", "tam", "arquivo"))
        headings = {
            "tipo": self._t("column_type"),
            "nome": self._t("column_title"),
            "id": self._t("column_code"),
            "ver": self._t("column_version"),
            "tam": self._t("column_size"),
            "arquivo": self._t("column_file"),
            "status": self._t("column_status"),
        }
        widths = {
            "tipo": (120, "w"),
            "nome": (180, "w"),
            "id": (85, "center"),
            "ver": (65, "center"),
            "tam": (80, "e"),
            "arquivo": (160, "w"),
            "status": (110, "w"),
        }
        for column in self.package_columns:
            self.tree.heading(column, text=headings[column])
            width, anchor = widths[column]
            self.tree.column(column, width=width, anchor=anchor)
        scroll_tree = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        scroll_horizontal = ttk.Scrollbar(list_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_tree.set, xscrollcommand=scroll_horizontal.set)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_tree.grid(row=0, column=1, sticky="ns")
        scroll_horizontal.grid(row=1, column=0, sticky="ew")

        dest_frame = tk.Frame(root)
        dest_frame.pack(fill="x", padx=10, pady=4)

        dest_label = tk.Label(dest_frame, text=self._t("destination"), font=("Segoe UI", 9, "bold"))
        dest_label.grid(row=0, column=0, sticky="w", padx=2, pady=2)
        self.ui["destination"] = dest_label

        self.entry_dest = tk.Entry(dest_frame)
        self.entry_dest.insert(0, self.default_dest)
        self.entry_dest.grid(row=1, column=0, sticky="we", padx=2, pady=2)
        dest_frame.columnconfigure(0, weight=1)

        self.btn_pick_dest = tk.Button(dest_frame, text=self._t("choose_folder"), command=self.pick_dest, width=15)
        self.btn_pick_dest.grid(row=1, column=1, sticky="w", padx=4, pady=2)
        self.ui["choose_folder"] = self.btn_pick_dest

        options_frame = tk.Frame(dest_frame)
        options_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        options_frame.columnconfigure((0, 1), weight=1, uniform="options")

        selection_frame = tk.LabelFrame(
            options_frame, text=self._t("selection_frame"), font=("Segoe UI", 10, "bold"),
            bg="#edf4ff", fg="#174a7e", padx=8, pady=4)
        selection_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self.ui["selection_frame"] = selection_frame
        self.var_selected_pkgs = tk.BooleanVar(value=False)
        self.selection_controls = []
        for key, value in (("all_packages", False), ("selected_packages", True)):
            control = tk.Radiobutton(
                selection_frame, text=self._t(key), variable=self.var_selected_pkgs,
                value=value, command=self._on_selection_mode, font=("Segoe UI", 9),
                bg="#edf4ff", activebackground="#edf4ff", anchor="w")
            control.pack(fill="x")
            self.selection_controls.append(control)
        selection_hint = tk.Label(selection_frame, text=self._t("selection_hint"),
                                  font=("Segoe UI", 9), bg="#edf4ff", fg="#174a7e",
                                  wraplength=310, justify="left", anchor="w")
        selection_hint.pack(fill="x", padx=3, pady=(3, 0))
        self.ui["selection_hint"] = selection_hint

        organization_frame = tk.LabelFrame(
            options_frame, text=self._t("organization_frame"), font=("Segoe UI", 10, "bold"),
            padx=8, pady=4)
        organization_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        self.ui["organization_frame"] = organization_frame
        self.var_merge_update = tk.BooleanVar(value=DEFAULT_MERGE_UPDATE)
        self.chk_merge_update = tk.Checkbutton(
            organization_frame, text=self._t("merge_update"), variable=self.var_merge_update,
            font=("Segoe UI", 9), anchor="w")
        self.chk_merge_update.pack(fill="x")
        merge_help = tk.Label(organization_frame, text=self._t("merge_help"),
                              font=("Segoe UI", 8), fg="#505050", anchor="w")
        merge_help.pack(fill="x", padx=4)
        self.ui["merge_help"] = merge_help

        self.var_extract_here = tk.BooleanVar(value=False)
        self.chk_extract_here = tk.Checkbutton(
            organization_frame, text=self._t("extract_here"),
            variable=self.var_extract_here, font=("Segoe UI", 9), anchor="w",
            command=self._on_toggle_extract_here)
        self.chk_extract_here.pack(fill="x")
        extract_help = tk.Label(organization_frame, text=self._t("extract_here_help"),
                                font=("Segoe UI", 8), fg="#505050", anchor="w")
        extract_help.pack(fill="x", padx=4)
        self.ui["extract_here_help"] = extract_help

        after_frame = tk.LabelFrame(
            options_frame, text=self._t("after_frame"), font=("Segoe UI", 10, "bold"),
            bg="#fff5e6", fg="#714500", padx=8, pady=3)
        after_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self.ui["after_frame"] = after_frame
        self.var_delete_pkg = tk.BooleanVar(value=False)
        self.chk_delete_pkg = tk.Checkbutton(
            after_frame, text=self._t("delete_pkg"),
            variable=self.var_delete_pkg, font=("Segoe UI", 9), anchor="w",
            bg="#fff5e6", activebackground="#fff5e6")
        self.chk_delete_pkg.pack(side="left")
        self.ui.update({"merge_update": self.chk_merge_update,
                        "extract_here": self.chk_extract_here,
                        "delete_pkg": self.chk_delete_pkg})
        delete_help = tk.Label(after_frame, text=self._t("delete_help"),
                               font=("Segoe UI", 9), bg="#fff5e6", fg="#714500",
                               anchor="w")
        delete_help.pack(side="left", padx=8)
        self.ui["delete_help"] = delete_help

        action_frame = tk.Frame(root)
        action_frame.pack(fill="x", padx=10, pady=4)

        self.btn_go = tk.Button(
            action_frame,
            text=self._t("extract"),
            command=self.start_batch_extraction,
            bg="#2e7d32",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            padx=10,
            pady=4,
            state="disabled"
        )
        self.btn_go.pack(side="left", padx=4)

        self.btn_cancel = tk.Button(action_frame, text=self._t("cancel"), command=self.cancel, state="disabled", width=12, pady=4)
        self.btn_cancel.pack(side="left", padx=4)
        self.ui["cancel"] = self.btn_cancel

        self.cpu_frame = tk.Frame(action_frame)
        self.cpu_frame.pack(side="right", padx=6)

        self.lbl_cpu = tk.Label(self.cpu_frame, text=f"{self._t('cpu')} 0%", font=("Segoe UI", 9, "bold"), fg="#1565c0", width=9, anchor="e")
        self.lbl_cpu.pack(side="left", padx=2)

        self.cpu_bar = ttk.Progressbar(self.cpu_frame, length=65, maximum=100, mode="determinate")
        self.cpu_bar.pack(side="left", padx=2)

        self.lbl_status = tk.Label(action_frame, text=self._t("waiting"), font=("Segoe UI", 9), anchor="w")
        self.lbl_status.pack(side="left", fill="x", expand=True, padx=8)

        self.bar = ttk.Progressbar(root, maximum=100, mode="determinate")
        self.bar.pack(fill="x", padx=10, pady=4)

        log_frame = tk.LabelFrame(root, text=self._t("history_frame"), font=("Segoe UI", 8), padx=4, pady=4)
        log_frame.pack(side="bottom", fill="x", padx=10, pady=4, before=list_frame)
        self.ui["history_frame"] = log_frame

        self.txt = tk.Text(log_frame, height=4, font=("Consolas", 9))
        scroll_txt = ttk.Scrollbar(log_frame, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=scroll_txt.set)
        self.txt.pack(side="left", fill="both", expand=True)
        scroll_txt.pack(side="right", fill="y")

    def log(self, msg):
        self.txt.insert("end", self._translate_runtime(msg) + "\n")
        self.txt.see("end")

    def _post(self, action, *args):
        self._events.put((action, args))

    def _poll_events(self):
        for _ in range(100):
            try:
                action, args = self._events.get_nowait()
            except queue.Empty:
                break
            try:
                action(*args)
            except Exception:
                self.root.report_callback_exception(*sys.exc_info())
        self.root.after(20, self._poll_events)

    def close(self):
        if self.closing:
            return
        self.closing = True
        self.batch_cancelled.set()
        self._scan_cancelled.set()
        if self.active_extractor:
            self.active_extractor.cancel()
        self._close_when_ready()

    def _close_when_ready(self):
        if self.is_extracting or self.is_scanning or (self._worker and self._worker.is_alive()):
            self.root.after(50, self._close_when_ready)
        else:
            for timer in self.root.tk.call("after", "info"):
                self.root.after_cancel(timer)
            cleanup = getattr(self.root, "_drop_cleanup", None)
            if cleanup:
                cleanup()
            while not self._events.empty():
                self._events.get_nowait()
            self.root.destroy()

    def _show_message(self, dialog, *args):
        if not self.closing:
            dialog(*args)

    def set_language(self, language):
        if language not in LANGUAGE_TEXT or language == self.language:
            return
        self.language = language
        self.root.title(self._t("title"))
        self.language_button.config(text=self._t("language_button"))
        for key, widget in self.ui.items():
            widget.config(text=self._t(key))
        column_keys = {
            "tipo": "column_type",
            "nome": "column_title",
            "id": "column_code",
            "ver": "column_version",
            "tam": "column_size",
            "arquivo": "column_file",
            "status": "column_status",
        }
        for column, key in column_keys.items():
            self.tree.heading(column, text=self._t(key))
        self.selection_controls[0].config(text=self._t("all_packages"))
        self.selection_controls[1].config(text=self._t("selected_packages"))
        current_cpu = self.lbl_cpu.cget("text").split()[-1]
        self.lbl_cpu.config(text=f"{self._t('cpu')} {current_cpu}")
        self._on_selection_mode()
        self._render_package_list()
        self._fit_package_list()
        if self.is_scanning:
            self._set_status(self._t("scanning"))
        elif not self.is_extracting:
            self._set_status(self._t("queue_status", count=len(self.pkg_list))
                             if self.pkg_list else self._t("waiting"))

    def toggle_language(self):
        self.set_language("pt" if self.language == "en" else "en")

    def _on_selection_mode(self):
        self.chk_delete_pkg.config(state="disabled" if self.is_extracting else "normal")
        self.btn_go.config(text=self._t("extract_selected") if self.var_selected_pkgs.get()
                           else self._t("extract"))

    def _update_cpu(self):
        try:
            pct = get_cpu_percent()
            self.lbl_cpu.config(text=f"{self._t('cpu')} {pct:.0f}%")
            self.cpu_bar.config(value=pct)
        except Exception:
            pass
        try:
            self.root.after(1000, self._update_cpu)
        except Exception:
            pass

    def scan_current_folder(self):
        script_dir = _application_directory()
        self.log(self._t("searching_from", path=script_dir))
        self.add_pkgs([script_dir])

    def pick_files(self):
        files = filedialog.askopenfilenames(
            title=self._t("choose_files_title"),
            filetypes=[(self._t("pkg_files"), "*.pkg"), (self._t("all_files"), "*.*")]
        )
        if files:
            self.add_pkgs(files)

    def pick_folder(self):
        directory = filedialog.askdirectory(title=self._t("choose_folder_title"))
        if directory:
            self.add_pkgs([directory])

    def pick_dest(self):
        d = filedialog.askdirectory(title=self._t("choose_output_title"))
        if d:
            self.entry_dest.delete(0, "end")
            self.entry_dest.insert(0, d)

    def _on_toggle_extract_here(self):
        script_dir = str(_application_directory())
        if self.var_extract_here.get():
            self.saved_dest = self.entry_dest.get()
            self.entry_dest.config(state="normal")
            self.entry_dest.delete(0, "end")
            self.entry_dest.insert(0, script_dir)
            self.entry_dest.config(state="disabled")
            self.btn_pick_dest.config(state="disabled")
        else:
            self.entry_dest.config(state="normal")
            self.btn_pick_dest.config(state="normal")
            if hasattr(self, "saved_dest") and self.saved_dest:
                self.entry_dest.delete(0, "end")
                self.entry_dest.insert(0, self.saved_dest)

    def _selected_package_ids(self):
        return set(self.tree.selection())

    def _set_package_status(self, item, status):
        item["status"] = status
        self.tree.set(item["tree_id"], "status", self._status_text(status))

    def _package_values(self, item):
        return (
            self._category_label(item), item["title"], item["title_id"], item["app_ver"],
            item["size_str"], item["filename"], self._status_text(item["status"]))

    def _render_package_list(self):
        selected = self._selected_package_ids()
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)

        for item in sorted(self.pkg_list, key=_package_display_key):
            if "tree_id" not in item:
                item["tree_id"] = f"pkg_{self._next_tree_id}"
                self._next_tree_id += 1
            self.tree.insert("", "end", iid=item["tree_id"], values=self._package_values(item))
            if item["tree_id"] in selected:
                self.tree.selection_add(item["tree_id"])

    def clear_list(self):
        if self.is_extracting or self.is_scanning:
            return
        self.pkg_list.clear()
        self._render_package_list()
        self._fit_package_list()
        self.btn_go.config(state="disabled")
        self._set_status(self._t("list_cleared"))

    def _fit_package_list(self):
        style = ttk.Style(self.root)
        font = style.lookup("Treeview", "font") or "TkDefaultFont"
        heading_font = style.lookup("Treeview.Heading", "font") or "TkHeadingFont"
        rows = [self._package_values(item) for item in self.pkg_list]
        for index, col in enumerate(self.package_columns):
            width = int(self.root.tk.call("font", "measure", heading_font, self.tree.heading(col, "text")))
            for text in {row[index] for row in rows}:
                width = max(width, int(self.root.tk.call("font", "measure", font, text)))
            self.tree.column(col, width=width + 20, minwidth=width + 20, stretch=False)
        self.tree.configure(height=2)
        self.root.update_idletasks()
        max_height = max(self.root.minsize()[1], self.root.winfo_screenheight() - 100)
        if self.root.state() == "zoomed":
            max_height = self.root.winfo_height()
        row_height = int(ttk.Style(self.root).lookup("Treeview", "rowheight") or 20)
        available_rows = max(2, 2 + (max_height - self.root.winfo_reqheight()) // row_height)
        self.tree.configure(height=min(max(2, len(self.pkg_list)), available_rows))
        self.root.update_idletasks()
        if self.root.state() == "normal":
            main_width = sum(self.tree.column(col, "width")
                             for col in ("status", "tipo", "nome", "id", "ver", "tam")) + 60
            width = min(self.root.winfo_screenwidth() - 100, max(self.root.winfo_width(), main_width))
            height = min(max_height, max(self.root.winfo_height(), self.root.winfo_reqheight()))
            y = min(self.root.winfo_y(), max(0, self.root.winfo_screenheight() - height - 80))
            x = min(self.root.winfo_x(), max(0, self.root.winfo_screenwidth() - width - 40))
            self.root.geometry(f"{width}x{height}+{x}+{y}")

    def add_pkgs(self, paths):
        if self.is_extracting or self.is_scanning or self.closing:
            self.log(self._t("wait_current_operation"))
            return
        self.is_scanning = True
        self._scan_cancelled.clear()
        self.btn_go.config(state="disabled")
        self.btn_cancel.config(state="normal")
        self._set_status(self._t("scanning"))
        self._worker = threading.Thread(
            target=self._run_scan, args=(tuple(paths), tuple(self.pkg_list)), daemon=True)
        self._worker.start()

    def _run_scan(self, paths, existing):
        found, messages = [], []
        existing_paths = {item["path"] for item in existing}
        fingerprints = {}
        for item in existing:
            fingerprints.setdefault(item.get("fingerprint"), []).append(item)

        def check():
            if self._scan_cancelled.is_set():
                raise Cancelled()

        def candidates():
            ignored = {".git", ".codex", "$recycle.bin", "__pycache__"}
            for source in paths:
                check()
                source = Path(source).resolve()
                if source.is_dir():
                    for directory, dirs, files in os.walk(source):
                        check()
                        dirs[:] = sorted(d for d in dirs if d.lower() not in ignored)
                        for name in sorted(files):
                            check()
                            if name.lower().endswith(".pkg"):
                                yield (Path(directory) / name).resolve()
                elif source.suffix.lower() == ".pkg":
                    yield source

        try:
            for path in candidates():
                check()
                if path in existing_paths:
                    messages.append(self._t("duplicate_warning", filename=path.name))
                    continue
                info = inspect_pkg_quick(path, check)
                if not info or not info.get("valid"):
                    messages.append(self._t(
                        "read_pkg_error", filename=path.name,
                        error=info["error"] if info else self._t("file_not_found")))
                    continue
                fingerprint = info["fingerprint"]
                try:
                    duplicate = next((other for other in fingerprints.get(fingerprint, [])
                                      if other["path"].is_file()
                                      and _same_pkg_content(path, other["path"], check)), None)
                except OSError as error:
                    messages.append(self._t("compare_pkg_error", filename=path.name, error=error))
                    continue
                if duplicate:
                    messages.append(self._t(
                        "duplicate_ignored", filename=path.name, other=duplicate["filename"]))
                    continue
                existing_paths.add(path)
                fingerprints.setdefault(fingerprint, []).append(info)
                found.append(info)
        except Cancelled:
            messages.append(self._t("scan_cancelled"))
        except OSError as error:
            messages.append(self._t("scan_failed", error=error))
        except Exception as error:
            messages.append(self._t("analyze_failed", error=error))
        finally:
            self._post(self._finish_scan, found, messages)

    def _finish_scan(self, found, messages):
        self.is_scanning = False
        if self.closing:
            return
        for message in messages:
            self.log(message)
        self.pkg_list.extend(found)
        if found:
            self._render_package_list()
            self._fit_package_list()
            self.log(self._t("added", count=len(found)))
        elif not self.pkg_list:
            self.log(self._t("no_compatible"))
        self.btn_go.config(state="normal" if self.pkg_list else "disabled")
        self.btn_cancel.config(state="disabled")
        self._set_status(self._t("queue_status", count=len(self.pkg_list))
                         if self.pkg_list else self._t("no_packages"))

    def cancel(self):
        self.batch_cancelled.set()
        self._scan_cancelled.set()
        if self.active_extractor:
            self.active_extractor.cancel()
        if self.is_extracting or self.is_scanning:
            self.log(self._t("cancel_requested"))

    def start_batch_extraction(self):
        if not self.pkg_list or self.is_extracting or self.is_scanning or self.closing:
            return

        extract_here = self.var_extract_here.get()
        delete_pkg = self.var_delete_pkg.get()
        merge_update = self.var_merge_update.get()
        selected_only = self.var_selected_pkgs.get()
        items = tuple(self.pkg_list)
        if selected_only:
            highlighted = self._selected_package_ids()
            if not highlighted and len(items) == 1:
                highlighted = {items[0]["tree_id"]}
                self.tree.selection_set(items[0]["tree_id"])
            items = tuple(item for item in items if item["tree_id"] in highlighted)
            if not items:
                messagebox.showinfo(self._t("choose_package_title"), self._t("choose_package_message"))
                return
        if extract_here:
            out_path = _application_directory()
        else:
            dest_text = self.entry_dest.get().strip()
            if not dest_text:
                messagebox.showerror(self._t("error"), self._t("choose_output_message"))
                return
            out_path = Path(dest_text)

        if extract_here:
            titles = {item["title_id"] for item in items
                      if item.get("is_fake") and item.get("kind") in ("base", "update")}
            if len(titles) > 1:
                messagebox.showerror(self._t("invalid_destination"), self._t("different_games"))
                return
        self.batch_cancelled.clear()
        self.is_extracting = True
        for control in (*self.selection_controls, self.chk_merge_update, self.chk_extract_here,
                        self.entry_dest, self.btn_pick_dest):
            control.config(state="disabled")
        self._on_selection_mode()
        self.btn_go.config(state="disabled")
        self.btn_cancel.config(state="normal")

        self._worker = threading.Thread(target=self._run_batch, args=(out_path, extract_here, delete_pkg, merge_update, selected_only, items), daemon=True)
        self._worker.start()

    def _run_batch(self, out_base, extract_here=False, delete_pkg=False,
                   merge_update=DEFAULT_MERGE_UPDATE, selected_only=False, items=None):
        logf = lambda m: self._post(self.log, m)
        statusf = lambda s: self._post(self._set_status, s)
        barf = lambda v: self._post(self.bar.config, {"value": v})
        tree_statusf = lambda item, s: self._post(self._set_package_status, item, s)

        items = tuple(self.pkg_list) if items is None else items
        valid_items = [item for item in items if item.get("is_fake")]
        skipped_items = [item for item in items if not item.get("is_fake")]

        for sk in skipped_items:
            tree_statusf(sk, "Ignorado (oficial)")
            logf(self._t("official_warning", filename=sk["filename"]))

        if not valid_items:
            logf(self._t("no_extractable"))
            self._post(self._finish_batch)
            return

        sorted_items = sorted(valid_items, key=_pkg_sort_key)

        total_files = len(sorted_items)

        logf(self._t("start_extraction", count=len(sorted_items)))
        logf(self._t("mode_here" if extract_here else "mode_subfolder"))
        logf(self._t("destination_log", path=out_base))

        item = sorted_items[0]
        completed = 0
        try:
            game_folders = _game_folder_names(self.pkg_list)
            for idx, item in enumerate(sorted_items, 1):
                if self.batch_cancelled.is_set():
                    raise Cancelled()
                if not item["path"].is_file():
                    tree_statusf(item, "Arquivo ausente")
                    logf(self._t("missing_source", filename=item["filename"]))
                    continue
                tree_statusf(item, "Extraindo...")
                barf(0)
                statusf(self._t("preparing", index=idx, total=total_files, filename=item["filename"]))
                logf(f"\n--- [{idx}/{total_files}] {self._category_label(item)}: {item['title']} ({item['size_str']}) ---")

                target_dir = _target_directory(out_base, item, extract_here, merge_update, game_folders)
                if not extract_here and item["title_id"] not in game_folders:
                    logf(self._t("base_missing"))
                logf(self._t("extraction_folder", path=target_dir))

                self.active_extractor = PkgExtractor(item["path"], target_dir,
                                                     protected_paths=(entry["path"] for entry in self.pkg_list))
                if self.batch_cancelled.is_set():
                    self.active_extractor.cancel()

                self.active_extractor.parse_pkg(logf)
                if (item.get("source_stamp", self.active_extractor._parsed_stamp)
                        != self.active_extractor._parsed_stamp):
                    raise ValueError(self._t("package_changed"))
                self.active_extractor.scan_fs(logf)
                item_total = self.active_extractor.output_total
                progress_state = {"done": 0, "last_t": 0.0}
                statusf(self._t("extracting", index=idx, total=total_files, filename=item["filename"]))

                def on_block_progress(delta):
                    progress_state["done"] += delta
                    now = time.monotonic()
                    if (
                        progress_state["done"] >= item_total
                        or now - progress_state["last_t"] >= 0.25
                    ):
                        progress_state["last_t"] = now
                        pct = _progress_percent(progress_state["done"], item_total)
                        barf(pct)
                        done_mb = progress_state["done"] / (1024 * 1024)
                        total_mb = item_total / (1024 * 1024)
                        statusf(self._t(
                            "progress", index=idx, total=total_files, filename=item["filename"],
                            percent=pct, done=done_mb, total_mb=total_mb))

                self.active_extractor.extract(logf, on_block_progress)
                completed += 1
                barf(100)
                statusf(self._t("completed_file", index=idx, total=total_files, filename=item["filename"]))

                self.active_extractor = None

                tree_statusf(item, "Concluído")
                logf(self._t("completed_log", path=target_dir))

                if delete_pkg:
                    try:
                        item["path"].unlink()
                        logf(self._t("file_deleted", filename=item["filename"]))
                    except Exception as e_del:
                        logf(self._t("file_delete_failed", filename=item["filename"], error=e_del))

            if not completed:
                statusf(self._t("no_extractable"))
                logf(self._t("none_available_log"))
                return
            if completed < total_files:
                message = self._t("partial_success", completed=completed, total=total_files)
                statusf(message)
                logf(message)
                self._post(self._show_message, messagebox.showwarning, self._t("title"), message)
                return
            barf(100)
            statusf(self._t("success"))
            logf(self._t("selected_success_log" if selected_only else "all_success_log"))
            logf(self._t("launcher_help"))
            self._post(self._show_message, messagebox.showinfo, self._t("title"),
                       self._t("selected_success" if selected_only else "all_success"))
        except Cancelled:
            tree_statusf(item, "Cancelado")
            logf(self._t("cancel_log"))
            statusf(self._t("cancelled"))
        except Exception as e:
            tree_statusf(item, "Erro")
            logf(self._t("error_log", error=self._translate_runtime(e)))
            statusf(f"{self._t('error')}: {self._translate_runtime(e)}")
            self._post(self._show_message, messagebox.showerror, self._t("extract_error_title"),
                       self._t("extract_error_message", error=self._translate_runtime(e)))
        finally:
            self.active_extractor = None
            self._post(self._finish_batch)

    def _finish_batch(self):
        self.is_extracting = False
        for control in (*self.selection_controls, self.chk_merge_update, self.chk_extract_here):
            control.config(state="normal")
        for control in (self.entry_dest, self.btn_pick_dest):
            control.config(state="disabled" if self.var_extract_here.get() else "normal")
        self._on_selection_mode()
        self.btn_go.config(state="normal" if self.pkg_list else "disabled")
        self.btn_cancel.config(state="disabled")


def main():
    no_gui = "--no-gui" in sys.argv
    if AES is None:
        if no_gui or not _avisa_sem_crypto():
            print("Falta o componente pycryptodome. Rode: pip install pycryptodome")
        return 1

    if no_gui:
        args = [a for a in sys.argv[1:] if a != "--no-gui"]
        if len(args) != 2:
            print('Uso: python pkg_extractor.py --no-gui "arquivo.pkg" "pasta de saída"', file=sys.stderr)
            return 2
        try:
            ex = PkgExtractor(*args)
            ex.parse_pkg(print)
            if not ex.title_id:
                raise ValueError("não foi possível identificar o jogo deste pacote")
            _check_game_identity(ex.extract_dir, ex.title_id)
            ex.scan_fs(print)
            ex.extract(print)
        except (OSError, ValueError, struct.error) as error:
            print(f"Erro: {error}", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            print("Extração cancelada.", file=sys.stderr)
            return 130
        return 0

    initial_files = [a for a in sys.argv[1:] if not a.startswith("-")]

    if tk is None:
        print("O Python está sem o componente de janela (Tkinter). Use --no-gui para extrair pelo terminal.", file=sys.stderr)
        return 1
    tkinter_cwd = os.getcwd()
    if _FROZEN:
        os.chdir(sys._MEIPASS)
    try:
        root = tk.Tk()
    except tk.TclError:
        print("Não foi possível abrir a janela. Use --no-gui para extrair pelo terminal.", file=sys.stderr)
        return 1
    finally:
        if _FROZEN:
            os.chdir(tkinter_cwd)
    if sys.platform == "win32":
        try:
            root.iconbitmap(default="")
        except tk.TclError:
            pass
    App(root, initial_files=initial_files)
    root.mainloop()


if __name__ == "__main__":
    sys.exit(main())
