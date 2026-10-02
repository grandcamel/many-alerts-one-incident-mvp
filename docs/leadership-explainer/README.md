# MVP explainer for engineering leadership

The explainer follows the running Docker Compose MVP from a configured Grafana
alert group through serial Claude Runs to one evolving Jira Incident. It covers
architecture, an interactive lifecycle, the division of responsibilities, and the
evidence supporting current behavior versus future capabilities.

- [Interactive HTML](mvp-leadership-explainer.html): download and open in a browser.
  It is self-contained and makes no external API calls.
- [Five-page PDF briefing](mvp-leadership-explainer.pdf): printable landscape version.

The explainer is a dated snapshot based on repository revision
`f910a5b75c493056c3a3404d8cf543559cdaa2d1`, reviewed on 2 October 2026. Source links pin
that snapshot. The Run preflight note reflects `main` at `b576463`; preflight was
introduced after the snapshot in `d264103`. The 2 October lifecycle, latency and cost figures are attributed
separately to an owner-reported personal-site rehearsal in `sources.json`; the
linked 1 October findings record does not source those figures. Update the claims
and their evidence together when the MVP changes; recorded lifecycle success does not establish acceptance of every later
fix or of optional investigation.

## Files

`build_explainer.py` is the editable source. It generates the main HTML,
`architecture.html`, `lifecycle.html`, `controls.html`, `evidence.html`, and
`sources.json`. The four smaller HTML files are self-contained components for
embedding. The generated PDF is a separate browser print export.

## Rebuild

Run from the repository root with Python 3; the generator uses only the standard
library:

```sh
python3 docs/leadership-explainer/build_explainer.py
```

To refresh the PDF, open the generated main HTML in a browser, choose **Print /
Save PDF**, use A4 landscape, enable background graphics, and disable browser
headers and footers. The print styles show the lifecycle as a complete table and
place the briefing on five pages. Rebuilding HTML alone does not update the PDF.

The PDF can also be produced headless with Chrome (replace the placeholders with
the output file and the absolute path to the main HTML):

```sh
chrome --headless --no-pdf-header-footer --print-to-pdf="<file>" "file://<absolute path to the main HTML>"
```

On macOS, headless Chrome can keep running after it writes the file; stop it once
the PDF exists. Keep the narrow-layout media query limited to `screen`: headless
printing evaluates width queries before applying the A4 page size, and a print match
stacks the layout across twelve pages.

The build is otherwise reproducible: the generator deterministically regenerates
all five HTML files and `sources.json` from `build_explainer.py`, without network
access. PDF export remains a separate Chrome/browser step.

## Validation

The delivered HTML was checked in Chromium at widths of 390, 700, and 1100 pixels
without horizontal overflow or JavaScript errors. All six lifecycle stages, the
previous/next controls, the optional investigation branch and incoming shared
widget state were exercised. The five-page PDF was rendered and visually
inspected. No live Jira, Grafana or model acceptance was performed for this
documentation change.

The same visuals are also on a private
[ChatGPT Page](https://chatgpt.com/space/page_f4642cd6c5dc8191ab256d5d8d64cc6c).
That Page requires its own access, is not the repository source of truth, and does
not automatically follow repository edits. Native Page rendering was not
independently inspected.
