
import argparse, json, os, subprocess, sys, time
from datetime import date, datetime, timedelta
from pathlib import Path

import requests

NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_HIST = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
GHSA_REPO = "https://github.com/github/advisory-database.git"
DEBIAN_URL = "https://security-tracker.debian.org/tracker/data/json"
REDHAT_VEX = "https://security.access.redhat.com/data/csaf/v2/vex/"

HOH_URL = "https://huggingface.co/datasets/russwest404/HoH-QAs/resolve/main/hoh_qas_240601_241201.parquet"

WINDOW_DAYS = 120
PAGE_CVES = 2000
PAGE_HIST = 5000
SLEEP_WITH_KEY = 0.7
SLEEP_NO_KEY = 6.5
UA = {"User-Agent": "ChronoRank-research-downloader/1.0"}
ALL_SOURCES = ["cves", "history", "kev", "epss", "ghsa", "debian", "hoh", "redhat"]
DEFAULT_SOURCES = [s for s in ALL_SOURCES if s != "redhat"]

class FatalAPIError(RuntimeError):
    pass

def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)

def atomic_write(fn: Path, data: bytes):

    tmp = fn.with_name(fn.name + ".part")
    tmp.write_bytes(data)
    os.replace(tmp, fn)

def get_json(url, params, headers, sleep, tries=6):
    for attempt in range(1, tries + 1):
        try:
            r = requests.get(url, params=params, headers={**UA, **headers}, timeout=180)
            msg = r.headers.get("message", "")
            if r.status_code == 200:
                data = r.json()
                time.sleep(sleep)
                return data
            if "apikey" in msg.lower():
                raise FatalAPIError(f"NVD API anahtarı reddedildi: '{msg}'. Anahtarın e-postadaki "
                                    f"link ile aktive edildiğini kontrol edin.")
            if r.status_code in (403, 429, 500, 502, 503, 504):
                wait = 30 * attempt
                log(f"  HTTP {r.status_code} {msg}, {wait}s bekleniyor (deneme {attempt}/{tries})")
                time.sleep(wait)
                continue
            raise FatalAPIError(f"HTTP {r.status_code} ({msg}) {url} {params}")
        except (requests.RequestException, ValueError) as e:
            wait = 15 * attempt
            log(f"  Hata: {e}; {wait}s sonra tekrar")
            time.sleep(wait)
    raise RuntimeError(f"Vazgeçildi: {url} {params}")

def iso(d: date, end=False):
    return f"{d:%Y-%m-%d}T{'23:59:59.999' if end else '00:00:00.000'}"

def windows(start: date, end: date):
    cur = start
    while cur <= end:
        nxt = min(cur + timedelta(days=WINDOW_DAYS - 1), end)
        yield cur, nxt
        cur = nxt + timedelta(days=1)

def download_nvd(endpoint, out_dir: Path, start, end, headers, sleep, date_param, page, list_key):
    out_dir.mkdir(parents=True, exist_ok=True)
    p_start, p_end = date_param
    grand = 0
    for ws, we in windows(start, end):
        idx, total = 0, 0
        while True:
            fn = out_dir / f"{ws:%Y%m%d}_{we:%Y%m%d}_{idx:07d}.json"
            if fn.exists():
                data = json.loads(fn.read_text(encoding="utf-8"))
            else:
                params = {p_start: iso(ws), p_end: iso(we, True),
                          "resultsPerPage": page, "startIndex": idx}
                data = get_json(endpoint, params, headers, sleep)
                atomic_write(fn, json.dumps(data).encode("utf-8"))
                log(f"  {fn.name}: {len(data.get(list_key, []))} kayıt "
                    f"({min(idx + page, data.get('totalResults', 0))}/{data.get('totalResults', 0)})")
            total = data.get("totalResults", 0)
            idx += page
            if idx >= total:
                break
        grand += total
        log(f"Pencere {ws}..{we} tamam (toplam {total})")
    log(f"{out_dir}: tüm pencerelerde toplam {grand} kayıt")

def check_nvd_key(headers):
    r = requests.get(NVD_CVES, params={"cveId": "CVE-2021-44228"}, headers={**UA, **headers}, timeout=60)
    if r.status_code != 200:
        raise FatalAPIError(f"NVD anahtar testi başarısız: HTTP {r.status_code} '{r.headers.get('message', '')}'. "
                            f"Anahtar yeni alındıysa NVD e-postasındaki aktivasyon linkine tıklayın.")
    log("NVD API anahtarı geçerli.")
    time.sleep(SLEEP_WITH_KEY)

def download_kev(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    fn = out_dir / "known_exploited_vulnerabilities.json"
    r = requests.get(KEV_URL, headers=UA, timeout=120); r.raise_for_status()
    data = r.json()
    atomic_write(fn, r.content)
    log(f"KEV: {len(data.get('vulnerabilities', []))} kayıt, katalog sürümü "
        f"{data.get('catalogVersion')} ({data.get('dateReleased')}) -> {fn}")

def download_epss(out_dir: Path, start: date, end: date, tries=4):
    out_dir.mkdir(parents=True, exist_ok=True)
    d = start
    ok = miss = have = 0
    missing = []
    while d <= end:
        ds = f"{d:%Y-%m-%d}"
        fn = out_dir / f"epss_scores-{ds}.csv.gz"
        if fn.exists():
            have += 1
        else:
            got = False
            for attempt in range(1, tries + 1):
                try:
                    r = requests.get(EPSS_URL.format(d=ds), headers=UA, timeout=180)
                    if r.status_code == 200 and r.content[:2] == b"\x1f\x8b":
                        atomic_write(fn, r.content); got = True
                        break
                    if r.status_code in (403, 404):
                        break
                    log(f"  EPSS {ds}: HTTP {r.status_code}, tekrar deneniyor")
                except requests.RequestException as e:
                    log(f"  EPSS {ds}: {e}, tekrar deneniyor")
                time.sleep(10 * attempt)
            if got:
                ok += 1
                if ok % 50 == 0:
                    log(f"  EPSS: {ok} gün indirildi (son: {ds})")
            else:
                miss += 1; missing.append(ds)
            time.sleep(0.3)
        d += timedelta(days=1)
    log(f"EPSS: {ok} yeni gün indirildi, {have} gün zaten vardı, {miss} gün bulunamadı")
    if missing:
        log(f"  Eksik günler: {', '.join(missing[:30])}{' ...' if len(missing) > 30 else ''}")

def download_ghsa(out_dir: Path):

    if (out_dir / ".git").exists():
        log(f"GHSA: mevcut repo güncelleniyor ({out_dir})")
        subprocess.run(["git", "-C", str(out_dir), "pull", "--ff-only"], check=True)
    else:
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        log(f"GHSA: clone başlıyor (~3.5 GB) -> {out_dir}")
        subprocess.run(["git", "-c", "core.longpaths=true", "clone", "--progress", GHSA_REPO, str(out_dir)],
                       check=True)
    head = subprocess.run(["git", "-C", str(out_dir), "log", "-1", "--format=%H %cI"],
                          capture_output=True, text=True, check=True).stdout.strip()
    n = sum(1 for _ in (out_dir / "advisories").rglob("*.json"))
    log(f"GHSA: {n} advisory JSON dosyası, HEAD {head}")

def download_debian(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    r = requests.get(DEBIAN_URL, headers=UA, timeout=600); r.raise_for_status()
    data = r.json()
    today = f"{date.today():%Y-%m-%d}"

    fn = out_dir / f"debian_tracker_{today}.json"
    atomic_write(fn, r.content)
    n_cve = sum(len(v) for v in data.values())
    log(f"Debian: {len(data)} kaynak paket, {n_cve} paket-CVE kaydı -> {fn}")

def download_hoh(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    fn = out_dir / HOH_URL.rsplit("/", 1)[-1]
    if fn.exists():
        log(f"HoH: {fn} zaten var"); return
    r = requests.get(HOH_URL, headers=UA, timeout=600); r.raise_for_status()
    if r.content[:4] != b"PAR1":
        raise RuntimeError("HoH: indirilen dosya parquet değil")
    atomic_write(fn, r.content)
    log(f"HoH: {len(r.content) / 1e6:.1f} MB -> {fn}")

def download_redhat(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    r = requests.get(REDHAT_VEX + "archive_latest.txt", headers=UA, timeout=60); r.raise_for_status()
    name = r.text.strip()
    fn = out_dir / name
    if fn.exists():
        log(f"Red Hat: {fn} zaten var"); return
    log(f"Red Hat: {name} indiriliyor")
    with requests.get(REDHAT_VEX + name, headers=UA, stream=True, timeout=600) as r:
        r.raise_for_status()
        tmp = fn.with_name(fn.name + ".part")
        size = 0
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk); size += len(chunk)
        os.replace(tmp, fn)
    log(f"Red Hat: {size / 1e6:.0f} MB -> {fn}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", required=True, help="YYYY-MM-DD")
    ap.add_argument("--end", required=True, help="YYYY-MM-DD")
    ap.add_argument("--out", default="data/raw")
    ap.add_argument("--api-key", default=None, help="NVD API key (default: env NVD_API_KEY)")
    ap.add_argument("--only", nargs="*", choices=ALL_SOURCES, help="run only these sources")
    ap.add_argument("--skip", nargs="*", default=[], choices=ALL_SOURCES)
    a = ap.parse_args()

    start = date.fromisoformat(a.start); end = date.fromisoformat(a.end)
    sources = [s for s in (a.only or DEFAULT_SOURCES) if s not in a.skip]
    out = Path(a.out)
    log(f"Kaynaklar: {sources}  aralık: {start}..{end}  çıktı: {out.resolve()}")

    try:
        if {"cves", "history"} & set(sources):
            key = a.api_key or os.environ.get("NVD_API_KEY")
            headers = {"apiKey": key} if key else {}
            sleep = SLEEP_WITH_KEY if key else SLEEP_NO_KEY
            if key:
                check_nvd_key(headers)
            else:
                log("UYARI: NVD_API_KEY yok, anahtarsız (çok yavaş) modda çalışılıyor.")
        if "cves" in sources:
            log("== NVD CVE kayıtları ==")
            download_nvd(NVD_CVES, out / "nvd/cves", start, end, headers, sleep,
                         ("pubStartDate", "pubEndDate"), PAGE_CVES, "vulnerabilities")
        if "history" in sources:
            log("== NVD CVE değişiklik geçmişi (en kritik) ==")
            download_nvd(NVD_HIST, out / "nvd/history", start, end, headers, sleep,
                         ("changeStartDate", "changeEndDate"), PAGE_HIST, "cveChanges")
    except FatalAPIError as e:
        log(f"DURDU: {e}")
        return 2
    if "kev" in sources:
        log("== CISA KEV =="); download_kev(out / "kev")
    if "epss" in sources:
        log("== EPSS günlük puanları =="); download_epss(out / "epss", start, end)
    if "ghsa" in sources:
        log("== GitHub Advisory Database =="); download_ghsa(out / "ghsa")
    if "debian" in sources:
        log("== Debian security tracker =="); download_debian(out / "debian/json")
    if "hoh" in sources:
        log("== HoH (alan-dışı test) =="); download_hoh(out / "hoh")
    if "redhat" in sources:
        log("== Red Hat CSAF VEX =="); download_redhat(out / "redhat")
    log("Bitti.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
