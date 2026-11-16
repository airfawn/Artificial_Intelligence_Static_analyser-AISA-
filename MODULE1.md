# Module 1: PE data collection

Install the command in the project's virtual environment using `pip install .`,
then activate that environment and run `aisa -f path/to/sample.exe` to collect
evidence without running the API analyzer. `--collect-only` or
`--collect-only=true` explicitly selects collection only;
`--collect-only=false` opts into experimental offline API analysis.
Alternatively, use `python main.py path/to/sample.exe` without
installing the project. Reinstall after changing the source or trained weights.
Run `aisa -h` for options. `aisa -a sample.exe` collects all data, while
`aisa -p sample.exe` performs only the packing assessment (without unpacking,
string extraction, or API collection). Omitting the mode retains full collection.
The report is displayed in the terminal and saved next to the input as
`sample.exe.report.pdf` by default. Select `--format pdf`, `--format json`, or
`--format text` (`-format` also works). Existing reports are not overwritten:
subsequent runs use `.report.1.pdf`, `.report.2.pdf`, and so on.
Use `-s path/to/report.pdf --format pdf` to choose a new output file. For
compatibility, `-s path/to/report.json` without a format and the legacy `-j` /
`--json` options produce JSON. Use `--min-len 4` to set the minimum string length.
The terminal, PDF, and text reports list strings in descending model-score order.
JSON retains extraction order to preserve category evidence indices and provides
`ranked_string_indices` for the same ranking; unscored strings come last.
Scores and unverified family associations are leads, not verdicts.
Run `aisa --version` to display the product version; the version source used by
the Python package and both installers is `aisa_version.py`.
An explicitly named output file must not already exist. Exit code 0 means the
collection completed, 2 means it is incomplete, and 1 means an I/O or input
error prevented completion, including an AI failure. A complete collection is
still saved if the AI fails; see `ai_analysis.error` in the report. An incomplete
collection skips AI analysis and returns 2.

The original file's MD5 and SHA-256 are reported along with PE section names,
sizes, entropy, and packing indicators. If the file looks UPX-packed and `upx`
is on PATH, the tool attempts to unpack a temporary copy. It collects strings
and APIs only if the resulting file is a valid PE without packing indicators.
Otherwise, the incomplete report asks for an unpacked file. Static API tables
from the packed original are retained separately in `packed_file_apis`; these
may describe a loader rather than the unpacked program and are not proof of
execution. The original file
is not changed; successful unpacking reports separate original and unpacked
hashes. Packing detection is heuristic and can have false positives or misses.
The report identifies UPX, ASPack, MPRESS, FSG, Themida, VMProtect, PECompact,
NsPack, MEW, and Enigma when recognizable section names are present. These
names are indicators, not proof: section names can be changed or spoofed, and
multiple matches are reported as ambiguous. Only an unambiguous UPX match is
passed to UPX; other or unknown packers require a separately unpacked file.
ASPack and MPRESS identification is based on section names only; they are not
automatically unpacked, and renamed sections can evade identification.

The report also includes an **experimental weighted packing score** between 0
and 1. It adds 0.40 for an exact known packer section name, 0.35 for a section
whose virtual and raw sizes meet the existing suspicious-discrepancy rule
(excluding `.data` and `.bss`), and 0.25 for any section with entropy above
7.0. The score is a manually weighted heuristic, not a trained model or a
probability. The report flags scores strictly greater than 0.6 (exactly 0.6 is
not above the threshold). Neither the score nor its flag changes the existing
packing gate or selects an unpacker; a low score does not prove a file unpacked.
Section names can be spoofed, and normal data can have high entropy or size
differences. On the existing held-out public UPX split, 7/7 UPX and 7/7
assumed-unpacked examples were classified correctly at this threshold.
This split was also used for prior model evaluation and is not an independent
evaluation of the complete workflow; it contains no ASPack, MPRESS, other
packers or malware. Results are in `data/packing_score_metrics.json` and the
per-sample indicators in `data/packing_score_dataset.json`. Reproduce with:

```text
python -m training.packing_public --output path/to/scored-data.json
python -m training.evaluate_packing_score --dataset path/to/scored-data.json --reference data/packing_public.json --output path/to/score-metrics.json
```

The evaluator verifies sample hashes, splits, labels, and existing feature
vectors against the earlier dataset; regeneration requires matching source
wheels and UPX output. A larger independent dataset is needed before using the
threshold for unpacking decisions.

For a report-only packing experiment, `training.packing_report_experiment`
adds CAPE reports with both `UPX0` and `UPX1` section names as weak UPX training
examples. These names can be spoofed; CAPE rounds entropy, so sections reported
at 7.00 are excluded. The candidate is not deployed:

```text
python -m training.packing_report_experiment --dataset data/packing_public.json --manifest data/local-cape/reports-v1/manifest.json --model data/local-cape/packing-candidate-v1.json --metrics data/local-cape/packing-candidate-v1-metrics.json
```

In the 206-report corpus described below, only one report supplied a usable
weak UPX example. Both the original model and the candidate classified 14/14
examples in the previously used test split correctly. This is not evidence of
improvement: there is no independently labeled CAPE test set, and the original
test split has already been used for model selection. No malware/benign
partition was used as a packing label.

The experimental nearest-centroid packing classifier reports a prediction and
distance using normalized section features. It has only two classes, `UPX` and
`unpacked`, and must pick one even for other packers. Its output is not proof
and does not influence identification, the packing gate, or unpacker selection.
The shipped model was trained on 16 original and 16 UPX-packed Windows
binary members from 10 public PyPI projects. Seven original/packed pairs from
four other projects are held out; all 14 were classified correctly. Project
separation is not proof of independent source lineage. The dataset includes at
most four packable members per wheel, from 64-bit Windows wheels only; it is
small, biased toward benign Python extension libraries, and excludes malware
and other packers. Original files are assumed unpacked, not independently
certified against other packers. These numbers do not establish real-world
accuracy. The feature-only `data/packing_public.json` records wheel URLs and
SHA-256 hashes, binary hashes, splits, exclusions and UPX version;
`data/packing_public_metrics.json` records the results. Binaries are not stored.
Create new outputs (the commands refuse to overwrite existing files) with:

```text
python -m training.packing_public --output path/to/dataset.json
python -m training.packing_baseline train --dataset path/to/dataset.json --model path/to/model.json --metrics path/to/metrics.json
```

Generation requires UPX and network access to PyPI; it verifies each wheel
against the hash returned by PyPI, processes its members without executing them,
and creates temporary UPX copies. Replacing the shipped model requires
deliberately deploying the newly trained file as `models/packing_model.json`
and rebuilding or reinstalling. Training must use representative labeled data
with independent source families and a held-out evaluation before predictions
can be relied upon. Existing string scores remain in place.

All extracted printable ASCII and UTF-16LE string occurrences are kept with
their offsets, lengths, encodings, and Shannon entropy. The existing locally
trained classifier annotates each string with a suspiciousness score and a
0.5-threshold flag; these are not readability scores or calibrated
probabilities. The model does not extract strings and no file verdict or
file-level correlation score is produced. If model weights are missing or
invalid, raw strings and available API data are still saved, but the report
is incomplete.

The report also categorizes candidates as domains, file paths, URLs, and
command-line strings. Categorization uses patterns, not the model, and a string
can appear in multiple categories. Each match includes a zero-based index into
`strings`, the source string's byte offset and encoding, and character offsets
within that string (`match_start` inclusive, `match_end` exclusive). Repeated
occurrences are preserved and category entries are sorted by value and source
offset. Commands are the entire source string when it contains a recognized
command interpreter or utility such as `cmd` or `powershell`; detection does not
prove that a command will execute. Matching is best effort: paths containing
spaces should be quoted, domains and paths can be ambiguous, and encoded or
constructed values can be missed. The original strings remain available.

PE normal imports, delay imports, and exports are reported separately, including
DLL names, API names or ordinals, and forwarders where available. Imported
functions are dependencies, not proof of execution. Dynamic, encrypted, or
runtime-resolved APIs may not appear in static PE tables. The JSON includes
parser warnings and directory parsing status; directory parse failures are
reported as incomplete rather than as an empty successful result. In JSON, an
absent directory has status `absent` and an empty list; an unreadable directory
has status `unreadable` and a `null` value because its contents are unknown.
Data collected from an unpacked file refers to the unpacked image.

## Experimental offline API analysis

With `--collect-only=false`, AISA adds offline API analysis under `ai_analysis`
in a complete collection report. This replaces Qwen on the CLI analysis path:
no server or network connection is used. To analyze an existing report:

```powershell
aisa --analyze-report "C:\Reports\sample.exe.report.json" --analysis-output "C:\Reports\sample.analysis.json"
```

In a source checkout, use `python main.py` in place of `aisa`. The output must
not already exist. Analysis requires a complete report and does not alter it.
Normal and delay imports are matched by name; each result references the actual
table and index. Ordinal-only imports cannot be analyzed, and names are not
validated against DLL identity. Exports are not treated as imports.

The frequency model counts each name once per sample in the available CAPE
normal import tables. The current model contains 49 malware-partition and 137
benign-partition samples, excluding 11 reports with missing imports and 9
duplicate samples. It records the most common imports overall and per automated
CAPE family label; the four usable families have only one or two samples each.
Family labels are unverified and matching a family-associated import does not
identify the analyzed sample's family. The corpus is small, biased and not an
independently evaluated malware benchmark.

The report flags imports with curated capability descriptions, plus other
imports appearing in at least three malware reports with a malware frequency
at least 0.15 greater than the benign frequency. It includes both raw counts
and denominators, and orders flags by that frequency difference. Five curated
import combinations have conservative possible-use descriptions and corpus
co-occurrence counts. It also reports learned pairs among curated APIs when
they meet the same minimum count and frequency-difference threshold. Those
thresholds are exploratory, not validated confidence or detection scores.
Descriptions are human-authored, not learned from the corpus. Co-occurrence
does not prove an interaction, intent, or execution, and common APIs have
legitimate uses. The model cannot determine malware type or establish a
verdict; a lack of indicators does not mean a file is safe.

To reproduce the model and print the ten most frequent imports per partition
and weak family (choose a new output path):

```text
python -m training.train_api_model data/local-cape/reports-v1/manifest.json --output path/to/api-model.json
```

The model is stored in `models/api_frequency_model.json`; raw reports are not
required at analysis time. Replacing the packaged model requires reinstalling
or rebuilding. The installer does not bundle Ollama or Qwen.

## Historical behavior-training experiments

The following Qwen-era tools and records are retained for research only.
They are not part of the installed product or the offline API analyzer.
Historical scripts are grouped under `training/legacy/`; existing generated
reports are grouped under `reports/`.

`training/download_pilot.py` downloads a pinned, non-representative pilot of
public CAPE **JSON reports only**, never executables. These reports include
dynamic sandbox observations, not reviewed labels for this static collector.
They must not be used as if dynamic observations were statically proven.
The SHA-256 manifest records provenance; downloaded reports may include
sensitive-looking malware indicators and must be handled as untrusted data.
The dataset card states MIT licensing; separately assess rights to upstream
sample and report content before redistribution.

An expanded local corpus can be collected explicitly with:

```text
python -m training.download_pilot --output data/local-cape/reports-v1 --per-class 50 --source malware --source benign --source portableapps --source installers --source sysinternals
```

The limit applies separately to each source; smaller sources contribute all
eligible reports. The manifest records source groups and checksums. The
`data/local-cape/` directory is ignored by Git and is local to this checkout:
back it up separately if needed. No reports are downloaded during analysis or
bundled automatically. Source partitions do not label packing status, and
neither malware nor benign implies packed or unpacked.

The current corpus has 50 malware, 50 Benign-NET, 6 PortableApps, 50 installer,
and 50 Sysinternals reports. A local review queue has 68 pending entries and
138 blocked: 118 exceed the former Qwen experiment's API context budget, 11 lack
static evidence, and 9 duplicate a sample. Blocked reports remain in the
corpus; no review or AI training is implied.

To prepare training data, create a JSON array of records from actual AISA
collection reports and analyst reviews. Each record requires `report` (path
relative to the review file), `split` (`train`, `valid`, or `test`), `reviewer`,
and `chosen` (the historical Qwen `hypotheses`/`summary` JSON shape).
For a CAPE report, add `"report_kind": "cape"`; the default is `"collector"`.
The adapter uses only CAPE static strings and normal imports, with offsets and
encoding unknown and without the collector's string scores or categories.
It does not fabricate collector reports or use dynamic activity as evidence.
Inspect the precise evidence IDs available for a CAPE review with
`python -m training.legacy.preview_cape path/to/report.json`.

To create a queue from the pilot manifest, then export completed reviews:

```text
python -m training.legacy.review_queue create path/to/manifest.json --output path/to/review-queue.json
python -m training.legacy.review_queue export path/to/review-queue.json --output path/to/reviews.json
python -m training.legacy.prepare_reviewed path/to/reviews.json --output path/to/reviewed-export
```

In the queue, `pending` entries have not been reviewed. Inspect each entry's
`model_prompt` (the exact evidence shown to the model) and `selected_evidence`
before adding a `chosen` analysis with evidence IDs. Set `reviewer`, `split`
and `status` to `reviewed` only after review. Optional rejected responses require
a preference reason. `blocked` entries include a reason (for example, duplicate
samples or API evidence exceeding the context budget); do not mark them reviewed
without resolving it. Dataset partitions are provenance, not evidence or
behavior labels. No split is assigned automatically: group related samples and
families in the same split to limit leakage. Export checks report hashes and
validates reviewed evidence IDs; it does not verify claims or reviewer identity.

For provisional external-teacher labels, generate a separate packet with:

```text
python -m training.legacy.teacher_packet path/to/review-queue.json --output path/to/new-teacher-packet
```

The packet contains an instruction file, batches of at most five cases using
the exact selected model evidence, and a local case mapping. No reports are sent
automatically. Keep the mapping private; it contains local paths and hashes.
Batch values are untrusted extracted strings and can themselves include paths,
identifiers, or sensitive content, so inspect them and follow data-sharing
policy before any external use. Returned teacher labels remain unreviewed and
must be validated and evaluated; they are not automatically imported or trained.
Optional `rejected` is the full rejected response text and must be accompanied
by `preference_reason`. A reviewer's name does not prove label correctness;
review the evidence and ensure related samples/families do not cross splits.
For example:

```json
[
  {
    "report": "sample.report.json",
    "split": "train",
    "reviewer": "analyst",
    "chosen": {"hypotheses": [], "summary": "Insufficient evidence."},
    "rejected": "This definitely steals credentials.",
    "preference_reason": "Static evidence does not establish credential theft."
  }
]
```

Provide reviewed examples in all three splits, then from the repository root run:

```text
python -m training.legacy.prepare_reviewed reviews.json --output reviewed-export
```

The export uses the historical Qwen evidence selection and prompt, verifies
chosen evidence IDs and rejects duplicate sample hashes, and emits supervised
chat JSONL and separate preference JSONL. It is not a training run and does not
perform reinforcement learning or establish model quality. Representative,
independently reviewed data is required before treating a fine-tuned model as
reliable.

## Historical experimental weak-label training

The local-only `training.legacy.weak_supervision` tool creates an experimental SFT
dataset without claiming analyst review. It supplies CAPE static strings and
imports to the student, and gives a local teacher the source partition and
sandbox signatures as weak hints. The hints are not student evidence and do
not prove that a static artifact caused an observed behavior. The teacher can
still generate unsupported claims even when every cited ID exists. Generated
labels require inspection and must not be treated as ground truth.

For example, after downloading the reports and making `qwen3:14b` available on
a local Ollama server:

```text
python -m training.download_pilot --output path/to/reports --per-class 50
python -m training.legacy.weak_supervision path/to/reports/manifest.json --output path/to/weak-data --teacher qwen3:14b --port 11434
```

The teacher endpoint is restricted to loopback. Data, intermediate labels and
the final provenance file are stored locally; no inference-time download is
performed. `provenance.json` is written only after the whole generation
completes. Partial JSONL files are not a completed dataset; rerun the same
command with `--resume` to verify and continue an interrupted generation.
Splits group exact
static evidence, but can still contain related samples or families across
splits; the selected reports and source partitions are biased. Neither split
nor teacher agreement is an independent malware-accuracy benchmark.

On Apple silicon, an isolated environment with `mlx-lm` can train a local
Qwen3 adapter from those JSONL files and run `training.legacy.evaluate_weak` on the
test split. For an Ollama model already available on a local server, test the
same held-out examples with:

```text
python -m training.legacy.evaluate_weak --data path/to/weak-data --ollama-model qwen3:1.7b --port 11434 --output path/to/evaluation.json
```

Its citation overlap measures agreement with the teacher, not correctness.
Do not bundle an adapter without evaluating its actual generated claims and
verifying its runtime format. This experiment is SFT, not reinforcement
learning.

## Windows offline installer

The x64 Windows installer contains AISA, its Python runtime and dependencies,
the string, packing and API models, and UPX. No internet, Python, pip, or administrator access is
needed on the target machine. Run the installer and leave the PATH option
selected to use `aisa` in a newly opened Command Prompt or PowerShell window:

```powershell
aisa -h
aisa -f "C:\Samples\sample.exe"
aisa -f "C:\Samples\sample.exe" -s "C:\Reports\report.json" --collect-only=false
```

If PATH is not selected or a security policy blocks PATH changes, use the full
path instead, for example `& "$env:LOCALAPPDATA\Programs\AISA\aisa.exe" -h`
in PowerShell. Use Windows Apps settings to uninstall; the installer removes
the PATH entry it added, without removing an entry that was already present.
The installed UPX is used without putting UPX itself on PATH. The installer is
unsigned; Windows security software or organizational policies may block it.

The installer must first be built on a connected Windows x64 machine or via
the manually run GitHub Actions workflow `Build Windows offline installer`. That
workflow builds and tests the installer and provides the executable and its
`AISA-Setup-x64-*.bin` data files as a downloadable workflow artifact. Keep all
files together when transferring them to the isolated machine. It uses the
official UPX 5.0.2 archive verified by SHA-256. Building and transferring it
does not happen automatically. Any older installer checked into the repository
predates these changes and must not be mistaken for a freshly built installer.

To build locally on Windows, install x64 Python 3.12 and Inno Setup 6, then
download and extract the official Windows x64 UPX archive from
https://github.com/upx/upx/releases/tag/v5.0.2. In PowerShell, from the project folder:

```powershell
py -3.12 -m venv .build-venv
.\.build-venv\Scripts\python.exe -m pip install . pyinstaller==6.17.0
.\installer\windows\build.ps1 `
  -Python ".\.build-venv\Scripts\python.exe" `
  -InnoCompiler "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" `
  -UpxDirectory "C:\path\to\upx-5.0.2-win64"
```

The output includes `dist\windows\AISA-Setup-x64.exe` and adjacent data slices.
The UPX directory must contain
`upx.exe`, `COPYING`, and `LICENSE`; those files are included in the installer.
The build requires internet access unless its build dependencies are already
available locally. It checks the bundled UPX and runs a synthetic-PE smoke test
against the frozen executable, including offline API analysis. Distributors
should review the bundled UPX license and applicable
corresponding-source obligations. The GitHub workflow additionally tests
installation, the installed executable, PATH addition, and uninstallation.

## macOS offline installers

The manually run `Build macOS offline installers` workflow produces separate
unsigned `.pkg` artifacts for Apple silicon and Intel Macs. Each package includes
the Python runtime, dependencies, all three models, and a native UPX executable
with its licenses. Installing requires administrator authorization and places
the application under `/usr/local/lib/aisa` and the `aisa` command at
`/usr/local/bin/aisa`; these paths may replace an existing AISA installation.
The packages are not signed or notarized, so macOS Gatekeeper or organizational
policies may block them. Build on a macOS version compatible with the target.

To build locally on the intended architecture, install Python, PyInstaller and
UPX, then supply the UPX executable and the directory containing its `COPYING`
and `LICENSE` files:

```sh
python3 -m pip install . pyinstaller==6.17.0
python3 installer/macos/build.py --upx "$(brew --prefix upx)/bin/upx" \
  --upx-license-dir "$(brew --prefix upx)"
```

The package is written under `dist/macos`. The build verifies that UPX does not
depend on unbundled libraries and exercises the frozen application, including
PDF generation, all models, and real UPX unpacking without UPX on PATH. The
GitHub workflow additionally installs and tests the resulting package.
