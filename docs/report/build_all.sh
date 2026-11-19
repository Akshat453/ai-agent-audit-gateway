#!/usr/bin/env bash
# Rebuild the whole report: Mermaid diagrams, Python charts, screenshots, .docx, PDF (LibreOffice)
# and the two-pass TOC / List of Tables / List of Figures page numbering.
set -euo pipefail
cd "$(dirname "$0")"
figures/render_mermaid.sh
python3 figures/charts/rq1_latency.py
python3 figures/charts/seal_comparison.py
python3 figures/screenshots.py
python3 build_report.py
