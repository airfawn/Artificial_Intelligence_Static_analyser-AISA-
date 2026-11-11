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

## Windows offline installer

The x64 Windows installer contains AISA, its Python runtime and dependencies,
the trained model, and UPX. No internet, Python, pip, or administrator access is
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
workflow builds and tests the installer and provides the executable as a
downloadable workflow artifact. It uses official UPX 5.0.2 with a verified
SHA-256. Transfer the resulting `AISA-Setup-x64.exe` to the isolated machine
using an approved method. Building and transferring it does not happen
automatically.

To build locally on Windows, install x64 Python 3.12 and Inno Setup 6, then
download and extract the official Windows x64 UPX archive from
https://github.com/upx/upx/releases/tag/v5.0.2. In PowerShell, from the project
folder:

```powershell
py -3.12 -m venv .build-venv
.\.build-venv\Scripts\python.exe -m pip install . pyinstaller==6.17.0
.\installer\windows\build.ps1 `
  -Python ".\.build-venv\Scripts\python.exe" `
  -InnoCompiler "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" `
  -UpxDirectory "C:\path\to\upx-5.0.2-win64"
```

The output is `dist\windows\AISA-Setup-x64.exe`. The UPX directory must contain
`upx.exe`, `COPYING`, and `LICENSE`; those files are included in the installer.
The build requires internet access unless its build dependencies are already
available locally. It checks the bundled UPX and runs a synthetic-PE smoke test
against the frozen executable. Distributors should review UPX's bundled license
and corresponding-source obligations. The GitHub workflow additionally tests
installation, the installed executable, PATH addition, and uninstallation.
