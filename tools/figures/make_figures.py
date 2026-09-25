from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.text import Text

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "results" / "figures"
W = 6.30
MAIN_METHOD, SCOPE_VARIANT = "ChronoRank-Rule-Target", "ChronoRank-Rule-Corpus"
C = {"current": "#0072B2", "current_light": "#9ECAE1", "outdated": "#D55E00", "other": "#8172B3", "neutral": "#E6E6E6", "main": "#D3DCE6",
     "neutral_edge": "#555555", "excluded": "#F4F4F4", "excluded_edge": "#8A8A8A", "text": "#222222", "grey": "#9E9E9E", "grey_light": "#CFCFCF", "rule_corpus": "#7FB3D5"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.linewidth": 0.8, "pdf.fonttype": 42, "ps.fonttype": 42, "hatch.linewidth": 0.6})
FONTS: dict[str, float] = {}

def save(fig, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    sizes = [t.get_fontsize() for t in fig.findobj(Text) if t.get_text().strip() and t.get_visible()]
    FONTS[name] = round(min(sizes), 2)
    fig.savefig(OUT / f"{name}.pdf", bbox_inches="tight", pad_inches=0.03)
    fig.savefig(OUT / f"{name}.png", dpi=300, bbox_inches="tight", pad_inches=0.03)
    fig.savefig(OUT / f"{name}.eps", format="eps", bbox_inches="tight", pad_inches=0.03)
    plt.close(fig)

def box(ax, x, y, w, h, text, fc=C["neutral"], ec=C["neutral_edge"], ls="-", lw=0.9, fs=8.0, bold=False, hatch=None, tc=None, radius=0.015, z=3, textbg=None, clip=True):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={radius}", fc=fc, ec=ec, ls=ls, lw=lw, hatch=hatch, zorder=z, clip_on=clip))
    kw = dict(bbox=dict(fc=textbg, ec="none", pad=1.0)) if textbg else {}
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=tc or C["text"], fontweight="bold" if bold else "normal", zorder=z + 1, linespacing=1.25, **kw)

def arrow(ax, x0, y0, x1, y1, text=None, ls="-", lw=0.9, color="#333333", fs=8.0, tx=0.0, ty=0.0, pos=0.5, rad=0.0, clip=True):
    ax.add_patch(FancyArrowPatch((x0, y0), (x1, y1), arrowstyle="-|>", mutation_scale=9, lw=lw, ls=ls, color=color, zorder=4, shrinkA=0, shrinkB=0,
                                 connectionstyle=f"arc3,rad={rad}", clip_on=clip))
    if text:
        ax.text(x0 + (x1 - x0) * pos + tx, y0 + (y1 - y0) * pos + ty, text, fontsize=fs, ha="center", va="center", color=color, zorder=6, bbox=dict(fc="white", ec="none", pad=0.8))

def blank(h: float):
    fig, ax = plt.subplots(figsize=(W, h))
    fig.subplots_adjust(left=0.0, right=1.0, bottom=0.0, top=1.0)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    return fig, ax

def figure_1():
    fig, ax = plt.subplots(figsize=(W, 2.35))
    fig.subplots_adjust(left=0.0, right=1.0, bottom=0.0, top=1.0)
    ax.set_xlim(0, 10); ax.set_ylim(-1.15, 3.6); ax.axis("off")
    t_rep, x_end = 5.0, 9.5
    ax.annotate("", xy=(9.9, 0.6), xytext=(0.2, 0.6), arrowprops=dict(arrowstyle="-|>", lw=1.1, color="#333333"))
    ax.text(9.9, 0.40, "time", ha="right", va="top", fontsize=8.5)

    ax.add_patch(FancyBboxPatch((0.6, 1.35), t_rep - 0.6, 0.62, boxstyle="round,pad=0,rounding_size=0.06", fc=C["current"], ec=C["current"], zorder=2))
    ax.text((0.6 + t_rep) / 2, 1.66, "e1:  CVSS-B 9.8  (Critical)", ha="center", va="center", fontsize=9, color="white", zorder=3)
    ax.add_patch(FancyBboxPatch((t_rep, 1.35), x_end - t_rep, 0.62, boxstyle="round,pad=0,rounding_size=0.06", fc="white", ec=C["outdated"], ls="--", lw=1.3, hatch="///", zorder=2))

    ax.add_patch(FancyBboxPatch((t_rep, 2.25), x_end - t_rep, 0.62, boxstyle="round,pad=0,rounding_size=0.06", fc=C["current"], ec=C["current"], zorder=2))
    ax.text((t_rep + x_end) / 2, 2.56, "e2:  CVSS-B 7.3  (High)", ha="center", va="center", fontsize=9, color="white", zorder=3)

    ax.plot([t_rep, t_rep], [0.6, 3.02], color="#333333", lw=1.2, zorder=4)
    ax.text(t_rep, 3.08, "atomic replacement event (e1 removed, e2 added; same source chain)", ha="center", va="bottom", fontsize=8.5)
    for x, name, labs in ((2.7, "query time t1", [("e1 at t1: CURRENT", C["current"])]),
                          (7.3, "query time t2", [("e1 at t2: OUTDATED", C["outdated"]), ("e2 at t2: CURRENT", C["current"])])):
        ax.plot([x, x], [0.6, 1.3], color="#333333", lw=0.9, ls=":", zorder=4)
        ax.plot(x, 0.6, marker="v", color="#333333", ms=6, zorder=5)
        ax.text(x, 0.96, name, ha="center", va="center", fontsize=8.5, bbox=dict(fc="white", ec="#333333", lw=0.6, pad=2.0), zorder=6)
        for k, (lab, col) in enumerate(labs):
            ax.text(x, 0.12 - k * 0.48, lab, ha="center", va="top", fontsize=9, color=col, fontweight="bold")
    save(fig, "figure_1_temporal_problem")

def figure_2():
    fig, ax = blank(3.0)
    style = {"current": (C["current"], C["current"], "white", "-", None), "outdated": ("white", C["outdated"], C["outdated"], "--", "///"),
             "other": (C["other"], C["other"], "white", "-", None), "neutral": (C["neutral"], C["neutral_edge"], C["text"], "-", None)}
    cols = [("(a) BM25", [("OUTDATED target", "outdated"), ("CURRENT target", "current"), ("OTHER_SOURCE_CURRENT", "other"), ("other evidence", "neutral")]),
            ("(b) BM25 + Recency", [("CURRENT target", "current"), ("OUTDATED target", "outdated"), ("OTHER_SOURCE_CURRENT", "other"), ("other evidence", "neutral")]),
            (f"(c) {MAIN_METHOD}", [("CURRENT target", "current"), ("OTHER_SOURCE_CURRENT", "other"), ("other evidence", "neutral"), ("other evidence", "neutral")])]
    cw, ch, gap = 0.262, 0.118, 0.148
    for i, (title, items) in enumerate(cols):
        x0 = 0.005 + i * 0.322; xc = x0 + 0.042
        ax.text(xc + cw / 2, 0.985, title, ha="center", va="top", fontsize=8.2, fontweight="bold")
        for r, (label, kind) in enumerate(items):
            y = 0.795 - r * gap
            fc, ec, tc, ls, hatch = style[kind]
            box(ax, xc, y, cw, ch, label, fc=fc, ec=ec, ls=ls, hatch=hatch, tc=tc, fs=7.6, textbg="white" if kind == "outdated" else None)
            ax.text(x0 + 0.018, y + ch / 2, f"{r + 1}", ha="center", va="center", fontsize=9, fontweight="bold")
        ax.text(xc + cw / 2, 0.265, "...", ha="center", va="center", fontsize=11)
        if i == 2:
            fc, ec, tc, ls, hatch = style["outdated"]
            box(ax, xc, 0.03, cw, ch, "OUTDATED target", fc=fc, ec=ec, ls=ls, hatch=hatch, tc=tc, fs=7.6, textbg="white")
            ax.text(x0 + 0.018, 0.03 + ch / 2, ">10", ha="center", va="center", fontsize=7.6, fontweight="bold")
            arrow(ax, xc + cw + 0.010, 0.795 + ch / 2, xc + cw + 0.010, 0.03 + ch / 2, rad=-0.16, color=C["outdated"], lw=1.1, clip=False)
            ax.text(xc + cw + 0.062, 0.47, "moved below the top-10", ha="center", va="center", fontsize=7.2, color=C["outdated"], rotation=90, clip_on=False)
    ax.plot([0.005, 0.965], [0.205, 0.205], color="#444444", lw=1.0, ls="--")
    ax.text(0.005, 0.212, "top-10 boundary", ha="left", va="bottom", fontsize=7.4, color="#444444")
    save(fig, "figure_2_ranking_comparison")

def figure_3():
    hist = json.loads((ROOT / "results" / "data_profiles" / "nvd_history_profile.summary.json").read_text(encoding="utf-8"))
    cand = json.loads((ROOT / "results" / "data_profiles" / "cvss_replacement_candidate_report.summary.json").read_text(encoding="utf-8"))
    atom = json.loads((ROOT / "data" / "processed" / "splits" / "atomic_replacement_manifest.json").read_text(encoding="utf-8"))
    bq = json.loads((ROOT / "data" / "processed" / "splits" / "base_query_eligible_manifest.json").read_text(encoding="utf-8"))
    n_changes, n_cand, n_strict = hist["total_changes"], cand["candidate_count"], cand["tier_counts"]["STRICT"]
    n_cand_excl = cand["tier_counts"]["EXCLUDED"]; n_elig = atom["scope"]["timeline_eligible_events"]; n_tl_excl = atom["scope"]["timeline_excluded_events"]
    n_bq = bq["main_split_events"] + bq["counts"]["future_event"]["events"]; ex = bq["excluded_by_detail"]; cnt = bq["counts"]
    n_nonbase = sum(ex[k] for k in ("THREAT_ONLY_CHANGE", "SUPPLEMENTAL_ONLY_CHANGE", "ENVIRONMENTAL_ONLY_CHANGE", "NO_BASE_COMPONENT_CHANGE"))
    fig, ax = blank(4.3)
    steps = [("NVD change history", f"{n_changes:,} change events"), ("CVSS replacement candidates", f"{n_cand:,} events"),
             ("Strict same-change candidates", f"{n_strict:,} events"), ("Timeline-eligible atomic events", f"{n_elig:,} events"),
             ("Base-query-eligible events", f"{n_bq:,} events"), ("Evidence and query generation", "source-conditioned queries, query-time labels")]
    ys = [0.945 - i * 0.131 for i in range(len(steps))]
    bx, bw, bh = 0.02, 0.52, 0.1
    for (t, s), y in zip(steps, ys):
        box(ax, bx, y - bh / 2, bw, bh, f"{t}\n{s}", fc=C["main"], ec="#333333", lw=1.0, fs=8)
    for y0, y1 in zip(ys[:-1], ys[1:]):
        arrow(ax, bx + bw / 2, y0 - bh / 2, bx + bw / 2, y1 + bh / 2, lw=1.0)
    side = [(1, f"excluded: {n_cand_excl} events\n(no metric change)"), (2, f"excluded: {n_tl_excl} events\n(chain ambiguity)"),
            (3, f"excluded: {n_nonbase} events without a Base change\n({ex['THREAT_ONLY_CHANGE']} Threat, {ex['SUPPLEMENTAL_ONLY_CHANGE']} Supplemental,\n"
                f"{ex['ENVIRONMENTAL_ONLY_CHANGE']} Environmental, {ex['NO_BASE_COMPONENT_CHANGE']} mixed)")]
    for idx, text in side:
        y = (ys[idx] + ys[idx + 1]) / 2
        hh = 0.118 if idx == 3 else 0.092
        box(ax, 0.60, y - hh / 2, 0.395, hh, text, fc=C["excluded"], ec=C["excluded_edge"], ls="--", fs=7, tc="#333333")
        arrow(ax, bx + bw / 2, y, 0.60, y, ls="--", color=C["excluded_edge"], lw=0.8)
    yb = 0.082
    splits = [("Train", cnt["train"], "2024–2025 events"), ("Development", cnt["dev"], "15% of training CVEs"), ("Future-entity test", cnt["test"], "2026, unseen CVEs"), ("Future-event", cnt["future_event"], "secondary analysis")]
    sw, sg = 0.238, 0.016
    for i, (name, c, note) in enumerate(splits):
        x = i * (sw + sg)
        secondary = name == "Future-event"
        box(ax, x, yb - 0.08, sw, 0.16, f"{name}\n{c['cves']:,} CVEs / {c['events']:,} events\n{note}", fc=C["excluded"] if secondary else C["main"],
            ec=C["excluded_edge"] if secondary else "#333333", ls="--" if secondary else "-", fs=7, tc="#333333" if secondary else C["text"])
        arrow(ax, bx + bw / 2, ys[-1] - bh / 2, x + sw / 2, yb + 0.08, ls="--" if secondary else "-", color=C["excluded_edge"] if secondary else "#333333", lw=0.8 if secondary else 1.0)
    save(fig, "figure_3_dataset_pipeline")

def figure_4():
    fig, ax = blank(2.45)
    stages = ["Source-\nconditioned\nquery", "Query-time\nvisible\ncorpus", "BM25\ntop-50\ncandidates", MAIN_METHOD.replace("-Rule", "-\nRule"), "Cleaned\ntop-10\nevidence", "Downstream\nRAG system\n\nNot evaluated"]
    n, bw, gap = len(stages), 0.150, 0.020
    y0, bh = 0.54, 0.43
    cx = []
    for i, t in enumerate(stages):
        x = i * (bw + gap)
        hi, last = i == 3, i == n - 1
        fc = "#DDEBF7" if hi else (C["excluded"] if last else C["neutral"])
        ec = C["current"] if hi else (C["excluded_edge"] if last else C["neutral_edge"])
        box(ax, x, y0, bw, bh, t, fc=fc, ec=ec, ls="--" if last else "-", lw=1.5 if hi else 0.9, fs=8 if not last else 7.6, bold=hi, tc="#333333" if last else C["text"])
        cx.append(x + bw / 2)
        if i < n - 1:
            arrow(ax, x + bw, y0 + bh / 2, x + bw + gap, y0 + bh / 2, ls="--" if i == n - 2 else "-", lw=1.0)
    labels = [(1, "query-time\ncutoff"), (2, "shared BM25\npool"), (3, "source-conditioned\nchain"), (3, "no reference labels\nas input"), (3, "no direct links")]
    lw_, lg = 0.188, 0.015
    for k, (src, text) in enumerate(labels):
        x = k * (lw_ + lg)
        box(ax, x, 0.03, lw_, 0.27, text, fc="white", ec="#666666", ls=":", fs=7.2, tc="#333333")
        ax.plot([cx[src], x + lw_ / 2], [y0, 0.30], color="#666666", lw=0.7, ls=":")
    ax.text(1.0, 0.42, "safety boundaries", ha="right", va="center", fontsize=7.2, color="#555555", style="italic")
    save(fig, "figure_4_system_architecture")

def figure_5():
    fig, ax = blank(4.35)
    qx, qw, qh = 0.27, 0.42, 0.105
    box(ax, qx, 0.915, qw, 0.07, "BM25 top-50 candidate  e", fs=8.6, bold=True)
    qs = [(0.745, "Is e in the query's chain\n(same CVE, source, CVSS version)?", "no", 0.035, 0.0),
          (0.555, "Is there a query-time-visible, newer\nassessment in the same chain?", "no", 0.035, 0.0),
          (0.365, "Is the newer Base vector different\nfrom the Base vector of e?", "no (same-value\nre-add)", -0.085, 0.035)]
    px, pw, py, ph = 0.785, 0.215, 0.42, 0.25
    box(ax, px, py, pw, ph, "Protected block\n(ranked first)\n\nkeep e, preserve\nBM25 order", fc="#DDEBF7", ec=C["current"], lw=1.4, fs=7.8)
    prev_bottom = 0.915
    for k, (y, q, no_text, ty, tx) in enumerate(qs):
        box(ax, qx, y, qw, qh, q, fc="#FFF5E0", ec="#B8860B", fs=8)
        arrow(ax, qx + qw / 2, prev_bottom, qx + qw / 2, y + qh, text="yes" if k else None, tx=0.04, fs=8)
        yt = py + ph * (0.84 - 0.34 * k)
        arrow(ax, qx + qw, y + qh / 2, px, yt, text=no_text, ty=ty, tx=tx, fs=7.6, pos=0.5)
        prev_bottom = y
    box(ax, 0.20, 0.17, 0.56, 0.10, "Inferred-superseded block (ranked second)\nmove e behind every protected candidate", fc="white", ec=C["outdated"], ls="--", hatch="///", tc=C["outdated"], fs=8, textbg="white")
    arrow(ax, qx + qw / 2, 0.365, qx + qw / 2, 0.27, text="yes", tx=0.04, fs=8)
    box(ax, 0.10, 0.0, 0.84, 0.105, f"{MAIN_METHOD} ranking\nprotected block first, inferred-superseded block second", fs=8, bold=True)
    arrow(ax, qx + qw / 2, 0.17, qx + qw / 2, 0.105)
    arrow(ax, px + pw / 2, py, px + pw / 2, 0.105)
    notes = [(0.555, "no evidence observed\nafter the query time"), (0.365, "no direct replacement\nlink is used")]
    for y, text in notes:
        box(ax, 0.0, y, 0.215, qh, text, fc="white", ec="#666666", ls=":", fs=7.2, tc="#333333")
        ax.plot([0.215, qx], [y + qh / 2, y + qh / 2], color="#666666", lw=0.7, ls=":")
    save(fig, "figure_5_chronorank_workflow")

def figure_6():
    fig_data = json.loads((ROOT / "results" / "paper_tables" / "figure_results_data.json").read_text(encoding="utf-8"))
    boot = json.loads((ROOT / "results" / "experiments" / "statistical_analysis" / "bootstrap_results.json").read_text(encoding="utf-8"))["results"]
    pts = {p["method"]: p for p in fig_data["points"]}
    n_q = fig_data["points"][0]["queries"]
    order = ["rule_target", "rule_corpus", "cross_encoder", "bm25_recency", "recency_only", "bm25"]
    names = {"bm25": "BM25", "recency_only": "Recency-only", "bm25_recency": "BM25 + Recency", "cross_encoder": "Cross-encoder", "rule_corpus": SCOPE_VARIANT, "rule_target": MAIN_METHOD}
    tone = {"rule_target": (C["current"], C["current_light"]), "rule_corpus": (C["rule_corpus"], "#C6DBEA")}
    panels = [("(a) Current evidence", [("current_preservation@10", "CurrentPreservation@10", True), ("top1_current_rate", "Top-1 CURRENT", False)]),
              ("(b) Stale evidence removal", [("outdated_suppression@10", "OutdatedSuppression@10", True), ("current_at1_and_no_stale@10", "CurrentAt1AndNoStaleAt10", True)])]
    fig, axes = plt.subplots(1, 2, figsize=(W, 3.0), sharey=True)
    h = 0.36
    for ax, (title, metrics) in zip(axes, panels):
        for j, (key, label, has_ci) in enumerate(metrics):
            ys = [i + (0.5 - j) * h for i in range(len(order))]
            for i, m in enumerate(order):
                v = pts[m][key]
                col = tone.get(m, (C["grey"], C["grey_light"]))[j]
                err = None
                if has_ci and m in boot:
                    lo, hi = boot[m][key]["ci95"]; est = boot[m][key]["estimate"]
                    err = [[max(0.0, est - lo)], [max(0.0, hi - est)]]
                ax.barh(ys[i], v, h, color=col, edgecolor="#333333", linewidth=0.5, hatch=["", "..."][j], xerr=err, error_kw=dict(lw=0.7, capsize=2, ecolor="#222222"), label=label if i == 0 else None)
                if j == 0:
                    ax.text(min(v, 1.0) + 0.03, ys[i], f"{v:.2f}", va="center", ha="left", fontsize=7)
        ax.set_yticks(range(len(order))); ax.set_yticklabels([names[m] for m in order], fontsize=7.6)
        ax.set_xlim(0, 1.16); ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0]); ax.set_xticklabels(["0", "0.25", "0.5", "0.75", "1"], fontsize=7.4)
        ax.set_title(title, fontsize=8.6, loc="left")
        ax.legend(fontsize=7.2, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=1, frameon=False, handlelength=1.4)
        ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    axes[0].invert_yaxis()
    fig.tight_layout(w_pad=1.0)
    axes[0].text(1.04, -0.43, f"rate on the future-entity test queries ({n_q:,}); error bars: 95% CVE-level cluster-bootstrap CI where defined",
                 transform=axes[0].transAxes, ha="center", va="top", fontsize=7)
    save(fig, "figure_6_results_comparison")

def gray_preview(out_dir: Path) -> None:
    import numpy as np
    from matplotlib import image as mpimg
    out_dir.mkdir(parents=True, exist_ok=True)
    for p in sorted(OUT.glob("figure_*.png")):
        img = mpimg.imread(p)[..., :3]
        g = (0.2126 * img[..., 0] + 0.7152 * img[..., 1] + 0.0722 * img[..., 2])
        mpimg.imsave(out_dir / f"{p.stem}_gray.png", np.stack([g, g, g], axis=-1))

def main(argv: list[str]) -> int:

    global OUT, MAIN_METHOD, SCOPE_VARIANT
    if "--out" in argv:
        OUT = Path(argv[argv.index("--out") + 1])
    if "--method-prefix" in argv:
        pre = argv[argv.index("--method-prefix") + 1]
        MAIN_METHOD, SCOPE_VARIANT = MAIN_METHOD.replace("ChronoRank", pre), SCOPE_VARIANT.replace("ChronoRank", pre)
    for fn in (figure_1, figure_2, figure_3, figure_4, figure_5, figure_6):
        fn()
    (OUT / "figure_fonts.json").write_text(json.dumps({"canvas_width_in": W, "min_font_pt": FONTS}, indent=2) + "\n", encoding="utf-8")
    if "--gray-preview" in argv:
        gray_preview(Path(argv[argv.index("--gray-preview") + 1]))
    print("yazildi:", sorted(p.name for p in OUT.iterdir()))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
