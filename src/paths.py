from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"

NVD_DIR = RAW_DATA_DIR / "nvd"
NVD_CVE_DIR = NVD_DIR / "cves"
NVD_HISTORY_DIR = NVD_DIR / "history"

KEV_DIR = RAW_DATA_DIR / "kev"
EPSS_DIR = RAW_DATA_DIR / "epss"
GHSA_DIR = RAW_DATA_DIR / "ghsa"
DEBIAN_DIR = RAW_DATA_DIR / "debian"
HOH_DIR = RAW_DATA_DIR / "hoh"

RESULTS_DIR = PROJECT_ROOT / "results"
DATA_PROFILE_DIR = RESULTS_DIR / "data_profiles"
QUALITY_ASSURANCE_DIR = RESULTS_DIR / "quality_assurance"
EXPERIMENTS_DIR = RESULTS_DIR / "experiments"
PAPER_TABLES_DIR = RESULTS_DIR / "paper_tables"

DOCS_DIR = PROJECT_ROOT / "docs"
TOOLS_DIR = PROJECT_ROOT / "tools"
TESTS_DIR = PROJECT_ROOT / "tests"
ARCHIVE_DIR = PROJECT_ROOT / "archive"

def create_output_directories() -> None:
    directories = [
        PROCESSED_DATA_DIR,
        RESULTS_DIR,
        DATA_PROFILE_DIR,
        QUALITY_ASSURANCE_DIR,
        EXPERIMENTS_DIR,
        PAPER_TABLES_DIR,
        DOCS_DIR,
    ]

    for directory in directories:
        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

def required_raw_directories() -> dict[str, Path]:
    return {
        "nvd_cves": NVD_CVE_DIR,
        "nvd_history": NVD_HISTORY_DIR,
        "kev": KEV_DIR,
        "epss": EPSS_DIR,
        "ghsa": GHSA_DIR,
        "debian": DEBIAN_DIR,
        "hoh": HOH_DIR,
    }

def validate_raw_directories() -> list[dict[str, str]]:
    missing = []

    for source_name, directory in (
        required_raw_directories().items()
    ):
        if not directory.is_dir():
            missing.append(
                {
                    "source": source_name,
                    "path": str(directory),
                }
            )

    return missing

def relative_to_project(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)
