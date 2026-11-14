# Historical training-data audit

## Decision

**Do not treat this pilot as analyst-validated or deployment-ready.** At the
user's request, an isolated weak-label SFT experiment was run after removing or
rewriting known unsupported claims. Its labels remain AI-generated, and the
model's held-out generation check failed. This experiment is not reinforcement
learning and does not establish malware-analysis accuracy.

## What was audited

- The 29 cases in the six Claude teacher-packet batches, matched to
  [output-claude.json](../../reports/legacy/output-claude.json) and the supplied corrections at
  `/Volumes/External-SSD/aisa-training-data/claude-teacher-packet/`.
- The existing review queue at `/Volumes/External-SSD/aisa-training-data/`.
- Citation validity using the evidence IDs actually supplied for each case.

The pilot contains 40 downloaded CAPE reports. Twenty-nine were included in the
teacher packet; 11 remain blocked from review. The CAPE adapter intentionally
uses static strings and imports, not dynamic behavior from the reports.

## Findings

1. **No reviewed examples are ready to export.** The review queue still has 29
   pending and 11 blocked cases. The training exporter requires a named
   reviewer and nonempty train, validation, and test splits; those approvals
   have not been recorded.
2. **Four cases had invalid citations** in the full response (`case-012`,
   `case-013`, `case-014`, and `case-028`). The supplied correction response
   repairs the citation IDs structurally, but does not resolve the semantic
   issues below.
3. **Signing is repeatedly inferred without verification.** Eighteen case
   analyses claim a Microsoft or Sectigo signature based on embedded PKI URLs,
   certificate-chain strings, or `.snk` build paths. These strings do not prove
   an Authenticode signature exists, is valid, or belongs to the named vendor.
   The same unsupported signing claims remain in the four corrected cases.
4. **Static artifacts are sometimes promoted to observed behavior.** Imports
   can support statements about potentially available APIs; strings can
   support statements about embedded references. Neither proves that the
   executable called an API, accessed a credential store, established a
   connection, or performed persistence. Several responses acknowledge this
   in their limitations but still phrase the hypothesis as established
   functionality.
5. **Confidence is not calibrated.** All 29 responses contain exactly three
   hypotheses in the same `high`, `medium`, `low` order. There is no
   independent evidence that these rankings correspond to probabilities or
   calibrated confidence.
6. **There are likely related examples.** The responses for cases 018/024
   describe very similar native GUI import patterns; cases 025/029 both
   identify Caspol-like policy tooling. Their sample hashes differ, so they
   are not exact duplicate samples, but related examples should be grouped
   during any future split to avoid leakage.
7. **This is not a suitable accuracy benchmark yet.** The 29 teacher answers
   are pseudo-labels, not ground truth. A small held-out subset from these
   same drafts would measure agreement with the teacher, not malware-analysis
   accuracy. The source malware/benign partition is not a label for the
   specific behavior described in each hypothesis.

## Recommended label corrections

- Replace signature assertions with wording such as “PKI or signing-related
  build strings are present; signature status was not verified” unless the
  file has been independently checked with Authenticode verification.
- Phrase static findings as evidence or capability, not execution. For
  example, report credential-store paths as “references to browser or wallet
  storage paths are embedded”; do not assert that credentials were read.
- Permit an empty hypothesis list and “insufficient static evidence” when
  appropriate. Do not force three ranked hypotheses.
- Record a reviewer and rationale for every accepted label. Keep rejected
  drafts as explicit preference examples only when a reviewer has written a
  clear, evidence-grounded reason.
- Group related tools or families before creating train/validation/test
  splits. Keep those splits separate from any later evaluation set.

## Preliminary case-by-case corrections

These are analyst recommendations for editing the drafts, not approvals or
ground-truth labels. Keep each case pending until a reviewer accepts or changes
the recommendation.

| Case | Recommended correction |
|---|---|
| 001 | Retain Go-runtime identification. Describe thread-context APIs as available imports only; they do not prove injection or debugging. |
| 002 | Retain the Hyper-V Virtual Machine Connection identification from its namespace and error strings. Remove the Microsoft-signature claim. |
| 003 | Recast as WinHTTP API capability, not a confirmed downloader or network activity. Imports alone do not prove the calls occur. |
| 004 | Retain ProtonVPN service identification from the PDB path, namespace, and named-pipe endpoint. Remove the signature claim. |
| 005 | Retain AddInProcess host identification. Treat `/pid` and `/guid` as argument strings, not proof of process targeting; remove the signature claim. |
| 006 | Describe Go runtime and registry-related code references. Do not say registry values or files were written based on symbol/import presence. |
| 007 | Reword “credential/wallet harvester” as possible targeting of wallet/browser storage paths. No read, collection, or exfiltration is observed. |
| 008 | Prefer “insufficient functional evidence.” A browser-config path, manifest, and build/signing artifacts do not identify a Microsoft tool. |
| 009 | Retain ProtonVPN TLS-verification component identification from its PDB path. Do not infer signing or execution from certificate URLs. |
| 010 | Retain Entity Framework EdmGen-style tool identification from its explicit usage strings. Remove the signature claim and avoid asserting generation occurred. |
| 011 | Retain Workflow Compiler host identification from its executable path and related type string. Remove the signature claim. |
| 012 | Retain VHD-inspection tool and WinForms-layout hypotheses from their names/XML. Remove the shell-integration/signature inference. |
| 013 | Retain Git Credential Manager askpass identification. Describe SSH regexes as embedded prompt patterns, not credential capture; remove signature assertions. |
| 014 | Prefer “insufficient functional evidence.” OS manifest GUIDs, PKI URLs, and type names do not prove signature or runtime behavior. |
| 015 | Retain AddInProcess host identification. Treat `/pid` and `/guid` as generic arguments; remove the signature claim. |
| 016 | Retain Go-runtime identification. ChaCha8 and WER imports/symbols are runtime/build evidence, not proof of cryptographic or reporting behavior. |
| 017 | Retain Mashup evaluation-container identification from its PDB and component strings. Working-set messages and an Office URL do not prove those behaviors or signing. |
| 018 | Describe a likely native GUI from the import set. Remove loader and keyboard-feature conclusions unless corroborated by stronger evidence. |
| 019 | Retain NGen service and fusion-log parsing hypotheses from the specific paths, flags, and regexes. Help strings do not prove a task ran. |
| 020 | Retain JScript compiler identification from JSC and usage strings; remove the VBScript-equivalent wording and signature claim. Merge the redundant output-target hypothesis. |
| 021 | Retain EdmGen identification from its explicit generation/validation arguments. Treat schema strings as static references; remove the signature claim. |
| 022 | Prefer “insufficient functional evidence.” DPI/OS manifest and `.snk` strings do not identify a signed .NET tool. |
| 023 | Reword as possible browser credential-store and persistence-command targeting. Do not claim harvesting, persistence, or privilege escalation occurred. |
| 024 | Describe a likely native GUI from imports. Treat loader and keyboard APIs as capabilities only, not confirmed behavior. |
| 025 | Retain Caspol-style policy-tool identification from its command and policy strings. Remove signing claims; a load-error string does not prove loading occurred. |
| 026 | Retain UE-V policy-generator identification from its explicit usage and assembly strings. A `requireAdministrator` manifest requests elevation; it does not prove elevated execution. |
| 027 | Describe Go/Windows runtime exception-handling support. Imports do not prove handlers were installed or indicate malicious functionality. |
| 028 | Retain TreeSize identification from its description string and likely GUI evidence. Remove Sectigo-signature and filesystem-enumeration claims. |
| 029 | Retain Caspol-style policy-tool identification. Remove signing claims and keep it grouped with case 025 for any data split. |

## Training status

An isolated QLoRA supervised fine-tuning pilot was run with MLX-LM 0.32.2 on
`mlx-community/Qwen3-1.7B-4bit`. The 29 AI-cleaned examples were split by
related cases into 23 train, four validation, and two test examples. Training
ran for 30 iterations over eight LoRA layers (rank 8; 2.49 million trainable
parameters). The base model and original Ollama model were not modified.

The adapter's test loss was 1.983 versus 4.652 for the base model on the same
two held-out pseudo-labels. Validation loss fell from 4.456 at the first
evaluation to 1.515 at the last. These values measure fit to this tiny,
AI-generated label set; they are not an accuracy result.

A free-generation smoke test on held-out prompts produced repetitive,
malformed JSON, so the adapter is **not ready for use or deployment**. The
Ollama schema-constrained inference path was not tested with this MLX adapter.
No reinforcement learning was run: the dataset has no reviewed preference
pairs or defensible behavior-grounded reward signal. The review queue still
contains zero approved cases.

A private, review-only packet was prepared at
`/Volumes/External-SSD/aisa-training-data/analyst-review-packet/`. It contains
all 29 drafts in six batches, overlays the four citation corrections, flags
unverified signature claims, and leaves each reviewer decision blank. It
intentionally omits sample hashes, source paths, and malware/benign partitions.

The experimental weak-label splits and provenance are at
`/Volumes/External-SSD/aisa-training-data/weak-label-sft-pilot/`; the adapter is
at `weak-label-sft-pilot/adapters/`. Keep these separate from reviewed training
data and do not bundle the adapter with the Windows installer.

A v2 copy at
`/Volumes/External-SSD/aisa-training-data/weak-label-sft-pilot-v2/` adds explicit
JSON-output instructions to each prompt. It preserves the same weak labels and
family-grouped 23/4/2 splits; it does not resolve label accuracy or make the
adapter deployable. The v2 run completed 30 iterations; validation loss fell
from 3.479 to 1.371. With the default chat template, both held-out free
generations included `<think>` tags. With Qwen3 thinking disabled, both
responses passed strict JSON and schema checks, but returned no hypotheses
and generic signature-related summaries despite more specific static evidence.
Thus, formatting passed but the analysis smoke test did not; citation validity
was not meaningfully exercised because there were no hypotheses. A separate
test-loss run measured 1.709 for the adapter versus 3.678 for the base model
on the same two weak-label examples; this indicates closer fit to those targets,
not accuracy. The base model also produced unsupported claims on one test case
and invalid field keys/citations on the other. The 29 targets pass structural,
word-limit, and evidence-ID checks, with a maximum tokenized sequence length
of 1,894 (below the 4,096 limit), but semantic label accuracy is unverified.
The Ollama schema-constrained path remains untested. The v2 adapter is
therefore still experimental and not for deployment; see `run-metadata.json`
in the v2 directory for the run details.

## Local-teacher weak-label pilot

A later experiment downloaded 100 pinned CAPE JSON reports (50 from each source
partition), without downloading or executing binaries. The first 20 usable
cases were selected evenly across partitions; 11 earlier reports were excluded
for duplicate hashes or exceeding the API evidence budget. A local
`qwen3:14b` teacher received source labels and sandbox signature descriptions as
unverified hints. The student's prompts contained only the selected static
strings and imports. The resulting 14 train, three validation, and three test
examples are machine-generated weak labels, not analyst-confirmed truth.
Grouping identical static evidence does not rule out related families in
different splits. The reports and partitions are not representative.

An MLX QLoRA run trained `mlx-community/Qwen3-1.7B-4bit` for 30 iterations
with eight LoRA layers, rank 8 and prompt masking. Validation loss fell from
2.303 to 0.776 against three weak labels; it is not an accuracy measure.
In unconstrained held-out generation, both the base model and the adapter
failed JSON or schema validation on all three cases.

For the actual Ollama-style constrained request, the pinned base model produced
structurally valid analyses for all three cases, but included unsupported or
misleading malware-type claims on benign-partition examples. The fused adapter
could not be imported by the standard Ollama safetensors importer; its
experimental importer accepted the model but did not honor the requested JSON
format or thinking setting. The adapted model failed all three constrained
requests, and still failed schema validation on all three when explicitly
prompted not to think. The labels themselves also contained unsupported
claims, including an unjustified self-modifying-code hypothesis.

These are small, weakly labeled smoke checks, not malware-detection accuracy
or calibration results. The adapter is experimental and must not replace the
pinned installer model on the basis of this run.
