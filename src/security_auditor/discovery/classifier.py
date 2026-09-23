"""Pure name, content, and shebang classification; no vulnerability decisions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from security_auditor.core.models import (
    ArtifactKind, Confidence, ContentKind, LanguageInfo, ManifestKind, ScriptKind,
)
from .sniffing import SniffResult


LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".pyw": "python", ".js": "javascript",
    ".mjs": "javascript", ".cjs": "javascript", ".jsx": "jsx",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".tsx": "tsx", ".ps1": "powershell", ".psm1": "powershell",
    ".bat": "batch", ".cmd": "batch", ".sh": "shell", ".bash": "shell",
    ".c": "c", ".h": "c", ".cpp": "c++", ".cc": "c++",
    ".cxx": "c++", ".hpp": "c++", ".cs": "c#", ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin", ".go": "go", ".rs": "rust",
    ".rb": "ruby", ".php": "php", ".swift": "swift", ".sql": "sql",
    ".html": "html", ".htm": "html", ".css": "css", ".json": "json",
    ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".xml": "xml",
    ".md": "markdown", ".markdown": "markdown",
}

SCRIPT_LANGUAGES = {
    "python": ScriptKind.PYTHON, "javascript": ScriptKind.JAVASCRIPT,
    "powershell": ScriptKind.POWERSHELL, "batch": ScriptKind.BATCH,
    "shell": ScriptKind.SHELL,
}

MANIFEST_NAMES = {
    "pyproject.toml": ManifestKind.PYTHON, "requirements.txt": ManifestKind.PYTHON,
    "pipfile": ManifestKind.PYTHON, "package.json": ManifestKind.NODE,
    "cargo.toml": ManifestKind.RUST, "go.mod": ManifestKind.GO,
    "pom.xml": ManifestKind.JAVA, "build.gradle": ManifestKind.JAVA,
    "build.gradle.kts": ManifestKind.JAVA, "gemfile": ManifestKind.RUBY,
    "composer.json": ManifestKind.PHP,
}
LOCK_NAMES = {
    "poetry.lock": ManifestKind.PYTHON, "uv.lock": ManifestKind.PYTHON,
    "pipfile.lock": ManifestKind.PYTHON, "package-lock.json": ManifestKind.NODE,
    "yarn.lock": ManifestKind.NODE, "pnpm-lock.yaml": ManifestKind.NODE,
    "cargo.lock": ManifestKind.RUST, "go.sum": ManifestKind.GO,
    "packages.lock.json": ManifestKind.DOTNET, "gemfile.lock": ManifestKind.RUBY,
    "composer.lock": ManifestKind.PHP,
}


@dataclass(frozen=True, slots=True)
class Classification:
    kind: ArtifactKind
    language: LanguageInfo
    script_kind: ScriptKind | None
    manifest_kind: ManifestKind | None
    executable_like: bool
    confidence: Confidence


def _shebang_language(line: str | None) -> str | None:
    if not line or not line.startswith("#!"):
        return None
    pieces = line[2:].lower().replace("\\", "/").split()
    if not pieces:
        return None
    interpreter = pieces[0].rsplit("/", 1)[-1]
    if interpreter == "env" and len(pieces) > 1:
        interpreter = next((part.rsplit("/", 1)[-1] for part in pieces[1:] if not part.startswith("-")), "")
    if interpreter.startswith("python"):
        return "python"
    if interpreter in {"node", "nodejs", "deno"}:
        return "javascript"
    if interpreter in {"pwsh", "powershell"}:
        return "powershell"
    if interpreter in {"bash", "sh", "zsh", "fish"}:
        return "shell"
    if interpreter.startswith("ruby"):
        return "ruby"
    if interpreter.startswith("php"):
        return "php"
    return None


def classify(relative_path: str, sniff: SniffResult) -> Classification:
    path = PurePosixPath(relative_path)
    name = path.name.lower()
    suffix = path.suffix.lower()
    if sniff.magic in {"pe", "elf", "mach_o"}:
        return Classification(ArtifactKind.EXECUTABLE, LanguageInfo(None), None, None, True, Confidence.HIGH)
    if sniff.magic in {"zip", "gzip"}:
        return Classification(ArtifactKind.ARCHIVE, LanguageInfo(None), None, None, False, Confidence.HIGH)
    if sniff.content_kind is ContentKind.BINARY:
        return Classification(ArtifactKind.BINARY, LanguageInfo(None), None, None, False, sniff.confidence)
    if sniff.content_kind is ContentKind.UNKNOWN:
        return Classification(ArtifactKind.UNKNOWN, LanguageInfo(None), None, None, False, Confidence.LOW)

    by_suffix = LANGUAGE_BY_SUFFIX.get(suffix)
    by_shebang = _shebang_language(sniff.first_line)
    language = by_shebang or by_suffix
    detection = "shebang" if by_shebang else "extension" if by_suffix else "unknown"
    confidence = Confidence.HIGH if language else Confidence.LOW
    language_info = LanguageInfo(language, detection=detection, confidence=confidence)
    script_kind = SCRIPT_LANGUAGES.get(language or "")

    if name in LOCK_NAMES:
        return Classification(ArtifactKind.LOCKFILE, language_info, None, LOCK_NAMES[name], False, Confidence.HIGH)
    if name in MANIFEST_NAMES or (name.startswith("requirements-") and name.endswith(".txt")) or suffix == ".csproj":
        manifest = MANIFEST_NAMES.get(name, ManifestKind.PYTHON if name.startswith("requirements-") else ManifestKind.DOTNET)
        return Classification(ArtifactKind.DEPENDENCY_MANIFEST, language_info, None, manifest, False, Confidence.HIGH)
    if name == ".env" or name.startswith(".env."):
        return Classification(ArtifactKind.ENV_FILE, language_info, None, None, False, Confidence.HIGH)
    if name in {"id_rsa", "id_ed25519"} or suffix in {".key", ".p12", ".pfx"} or name.startswith("private."):
        return Classification(ArtifactKind.KEY_MATERIAL_LIKE, language_info, None, None, False, Confidence.MEDIUM)
    if suffix in {".crt", ".cer", ".pem"}:
        return Classification(ArtifactKind.CERTIFICATE_LIKE, language_info, None, None, False, Confidence.MEDIUM)
    if relative_path.replace("\\", "/").lower().startswith(".github/workflows/") and suffix in {".yml", ".yaml"}:
        return Classification(ArtifactKind.CI_CONFIG, language_info, None, None, False, Confidence.HIGH)
    if name in {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return Classification(ArtifactKind.CONTAINER_CONFIG, language_info, None, None, False, Confidence.HIGH)
    if name in {"makefile", "nginx.conf", "security-auditor.toml"}:
        return Classification(ArtifactKind.CONFIG, language_info, None, None, False, Confidence.HIGH)
    if suffix in {".md", ".markdown", ".rst", ".txt"}:
        return Classification(ArtifactKind.DOCUMENTATION, language_info, None, None, False, Confidence.MEDIUM)
    if script_kind or by_shebang:
        if suffix in {".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}:
            return Classification(ArtifactKind.SOURCE_CODE, language_info, script_kind, None, False, Confidence.HIGH)
        return Classification(ArtifactKind.SCRIPT, language_info, script_kind or ScriptKind.OTHER, None, True, Confidence.HIGH)
    if suffix in {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".cs", ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".php", ".swift", ".sql"}:
        return Classification(ArtifactKind.SOURCE_CODE, language_info, None, None, False, Confidence.HIGH)
    if suffix in {".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".cfg", ".conf", ".properties"}:
        return Classification(ArtifactKind.CONFIG, language_info, None, None, False, Confidence.MEDIUM)
    return Classification(ArtifactKind.UNKNOWN, language_info, None, None, False, Confidence.LOW)
