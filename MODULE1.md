# Module 1: PE data collection

Install the command in the project's virtual environment using `pip install .`,
then activate that environment and run `aisa -f path/to/sample.exe` to inspect a
Windows PE file. Alternatively, use `python main.py path/to/sample.exe` without
installing the project. Reinstall after changing the source or trained weights.
Run `aisa -h` for options. The report
is displayed in the terminal and saved next to the input as
`sample.exe.report.json`. Existing reports are not overwritten: subsequent runs
use `.report.1.json`, `.report.2.json`, and so on. Use `-s path/to/report.json`
to select a new output file, and `--min-len 4` to set the minimum string length.
The aliases `-j` and `--json` remain available for the output path.
An explicitly named output file must not already exist. Exit code 0 means the
collection completed, 2 means it is incomplete, and 1 means an I/O or input
error prevented completion.

The original file's MD5 and SHA-256 are reported along with PE section names,
sizes, entropy, and packing indicators. If the file looks UPX-packed and `upx`
is on PATH, the tool attempts to unpack a temporary copy. It collects strings
and APIs only if the resulting file is a valid PE without packing indicators.
Otherwise, the incomplete report asks for an unpacked file. The original file
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
can be relied upon. Existing string scores remain in place and continue to
inform Qwen's evidence selection.

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

## Experimental offline behavior analysis

The optional baseline analyzes an existing complete collection report with the
local `qwen3:1.7b` model; it does not execute the sample. The Windows offline
installer includes a private Ollama runtime and model. AISA starts its own
loopback-only Ollama server when analysis begins and stops it afterward; it
does not use or alter a separately installed Ollama server or model store.
To run it after installing:

```powershell
aisa --analyze-report "C:\Reports\sample.exe.report.json" --analysis-output "C:\Reports\sample.analysis.json"
```

In a source checkout, use `python main.py` in place of `aisa` and start a local
Ollama server at `127.0.0.1:11434` with `qwen3:1.7b` installed. The output must
not already exist. The analysis is separate from collection and does not change
the source report. It selects declared API entries and prioritizes strings using
the existing suspicious flag, candidate categories and path markers, then
generates up to three ranked hypotheses. Selection is bounded, so the model
does not see every extracted string.
Output retains source indices and offsets; the program rejects nonexistent
evidence IDs, but cannot verify that a cited item supports the model's claim.
Long strings are truncated for the model and counted in the output. Evidence
selection counts are provided. If API evidence cannot fit the context budget,
analysis fails explicitly. Results are experimental, not malware verdicts:
evidence selection and reasoning may miss information or hallucinate.

The model uses a bounded 8192-token context, but total process memory and VM
performance depend on the runtime, hardware and workload. The 4 GB budget has
not yet been verified on FLARE VM. The installed private server is shut down
after analysis; for a manually run source-checkout server, use
`ollama stop qwen3:1.7b` to release model memory. Treat model output as untrusted.
Inference contacts only the local server; the private runtime disables Ollama
cloud features. Downloading build components requires network access. No
fine-tuning or malware-specific training is provided.

## Preparing reviewed behavior-training examples

`training/download_pilot.py` downloads a pinned, non-representative pilot of
public CAPE **JSON reports only**, never executables. These reports include
dynamic sandbox observations, not reviewed labels for this static collector.
They must not be used as if dynamic observations were statically proven.
The SHA-256 manifest records provenance; downloaded reports may include
sensitive-looking malware indicators and must be handled as untrusted data.
The dataset card states MIT licensing; separately assess rights to upstream
sample and report content before redistribution.

To prepare training data, create a JSON array of records from actual AISA
collection reports and analyst reviews. Each record requires `report` (path
relative to the review file), `split` (`train`, `valid`, or `test`), `reviewer`,
and `chosen` (the same `hypotheses`/`summary` JSON shape produced by analysis).
For a CAPE report, add `"report_kind": "cape"`; the default is `"collector"`.
The adapter uses only CAPE static strings and normal imports, with offsets and
encoding unknown and without the collector's string scores or categories.
It does not fabricate collector reports or use dynamic activity as evidence.
Inspect the precise evidence IDs available for a CAPE review with
`python -m training.preview_cape path/to/report.json`.

To create a queue from the pilot manifest, then export completed reviews:

```text
python -m training.review_queue create path/to/manifest.json --output path/to/review-queue.json
python -m training.review_queue export path/to/review-queue.json --output path/to/reviews.json
python -m training.prepare_reviewed path/to/reviews.json --output path/to/reviewed-export
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
python -m training.teacher_packet path/to/review-queue.json --output path/to/new-teacher-packet
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
python -m training.prepare_reviewed reviews.json --output reviewed-export
```

The export uses the same evidence selection and prompt as inference, verifies
chosen evidence IDs and rejects duplicate sample hashes, and emits supervised
chat JSONL and separate preference JSONL. It is not a training run and does not
perform reinforcement learning or establish model quality. A dataset large
enough for representative, independently reviewed training and held-out
evaluation is required before either fine-tuning or preference optimization.

## Windows offline installer

The x64 Windows installer contains AISA, its Python runtime and dependencies,
the string classifier, UPX, Ollama runtime, and Qwen3 1.7B. No internet, Python,
pip, separately installed Ollama, or administrator access is
needed on the target machine. Run the installer and leave the PATH option
selected to use `aisa` in a newly opened Command Prompt or PowerShell window:

```powershell
aisa -h
aisa -f "C:\Samples\sample.exe"
aisa -f "C:\Samples\sample.exe" -s "C:\Reports\report.json"
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
files together when transferring them to the isolated machine. It uses official
UPX 5.0.2, Ollama 0.32.5 and a pinned Qwen3 1.7B model, verified by SHA-256.
The installer and extracted runtime require several gigabytes of disk space.
Building and transferring it does not happen automatically.

To build locally on Windows, install x64 Python 3.12 and Inno Setup 6, then
download and extract the official Windows x64 UPX archive from
https://github.com/upx/upx/releases/tag/v5.0.2 and Ollama's
`ollama-windows-amd64.zip` from https://github.com/ollama/ollama/releases/tag/v0.32.5.
Put the Ollama release LICENSE alongside `ollama.exe`. Prepare a separate
Ollama model store containing the pinned `qwen3:1.7b` model. The build rejects
a different manifest or corrupted blob. In PowerShell, from the project folder:

```powershell
py -3.12 -m venv .build-venv
.\.build-venv\Scripts\python.exe -m pip install . pyinstaller==6.17.0
.\installer\windows\build.ps1 `
  -Python ".\.build-venv\Scripts\python.exe" `
  -InnoCompiler "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" `
  -UpxDirectory "C:\path\to\upx-5.0.2-win64" `
  -OllamaDirectory "C:\path\to\ollama" `
  -ModelDirectory "C:\path\to\ollama-models"
```

The output includes `dist\windows\AISA-Setup-x64.exe` and adjacent data slices.
The UPX directory must contain
`upx.exe`, `COPYING`, and `LICENSE`; those files are included in the installer.
The build requires internet access unless its build dependencies are already
available locally. It checks the bundled UPX and runs a synthetic-PE smoke test
against the frozen executable, including local model inference. Distributors
should review the bundled UPX, Ollama and Qwen licenses and applicable
corresponding-source obligations. The GitHub workflow additionally tests
installation, the installed executable, PATH addition, and uninstallation.
