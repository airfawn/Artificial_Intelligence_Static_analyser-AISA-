AISA

Artificial Intelligence Static Analyser

An offline, evidence-driven static analysis tool for Windows PE executables, combining lightweight machine learning, statistical analysis and curated detection patterns.

AISA is designed to assist malware analysts in examining suspicious Windows executables without requiring cloud-based analysis services.

It extracts and evaluates potentially interesting indicators from Portable Executable (PE) files, including strings, packing characteristics and imported APIs. Its findings are consolidated into structured reports that provide context for further investigation.

Rather than producing an unquestionable malware verdict, AISA focuses on presenting evidence that an analyst can examine and interpret.

⸻

Overview

Traditional static analysis involves examining executable files without running them. While this approach can reveal valuable information, manually correlating indicators across different parts of a binary can be time-consuming.

AISA explores how lightweight machine learning and statistical techniques can assist this process.

The project currently incorporates three primary analytical components:

Component	Methodology	Purpose
String Analysis	Sigmoid-based linear classifier	Rank potentially suspicious strings
Packing Assessment	Supervised nearest-centroid classifier	Assess potential executable packing
API Analysis	Corpus statistics and curated patterns	Highlight potentially interesting API imports and combinations

All three components operate locally using the available model assets and analysis data.

Key Features

* Offline Analysis: No cloud-based AI API is required for the core analysis workflow.
* PE Examination: Extracts information from Windows Portable Executable files.
* String Analysis: Extracts strings and ranks potentially suspicious indicators using a feature-based classifier.
* Packing Assessment: Uses a supervised nearest-centroid model to assess packing characteristics.
* UPX Support: Supports an unpacking workflow for UPX-packed executables.
* API Intelligence: Uses corpus-derived statistics and curated patterns to identify potentially interesting API calls.
* Evidence-Oriented Reporting: Presents findings in structured reports.
* Multiple Output Formats: Supports PDF, JSON and plain-text reports.
* CLI Interface: Provides command-line access to the analysis pipeline.

⸻

How AISA Works

AISA follows a packing-first analysis workflow.

             Windows PE Executable
                       |
                       v
              Initial PE Examination
                       |
                       v
                Packing Assessment
                       |
              +--------+--------+
              |                 |
          Appears packed     Not packed
              |                 |
              v                 |
       Packer Identification    |
              |                 |
              v                 |
        UPX Unpacking            |
              |                 |
              v                 |
       Validate Unpacked PE     |
              |                 |
              +--------+--------+
                       |
                       v
                Static Extraction
                       |
             +---------+---------+
             |         |         |
             v         v         v
          Strings    API Data   PE Metadata
             |         |         |
             v         v         |
       String Model  Statistical |
          Ranking     Analysis   |
             |         |         |
             +---------+---------+
                       |
                       v
                Evidence Report
                       |
                       v
              PDF / JSON / TXT

The workflow prioritises packing assessment before proceeding with the remaining extraction stages.

If unpacking is supported and successful, AISA validates the resulting executable before continuing its analysis.

⸻

Machine Learning & Analysis Methodology

AISA deliberately uses different analytical approaches for different problems instead of forcing every component into a single machine learning model.

1. String Analysis

AISA extracts strings from the executable and evaluates them using a feature-based linear classifier.

Model: Sigmoid-based linear classifier.

The model produces scores used to rank potentially suspicious strings.

The objective is to prioritise indicators that may deserve further analyst attention.

Strings are contextual indicators, not proof of malicious behaviour.

2. Packing Assessment

Packed executables can conceal information that would otherwise be available through static inspection.

AISA incorporates a supervised nearest-centroid classifier to assess executable packing characteristics.

Model: Supervised nearest-centroid classification.

The packing workflow includes:

* Packing assessment.
* Packer identification.
* UPX unpacking support.
* Validation of the resulting PE.
* Continuation of static extraction where possible.

Packing assessment is experimental and should not be treated as definitive packer identification.

3. API Analysis

API analysis uses corpus-derived statistics and curated patterns rather than a neural network.

The analysis examines potentially interesting Windows API imports and their relationships.

It incorporates:

* Statistical information derived from malware corpora.
* API frequency comparisons.
* Curated API patterns.
* Potentially interesting API combinations.
* Contextual information to support analyst interpretation.

An individual imported API does not establish that the executable actually invokes it.

Similarly, an API combination can suggest a possible capability without proving that the capability is implemented or executed.

⸻

Technology Stack

Technology	Purpose
Python	Core implementation
PEfile	Portable Executable examination
Machine Learning	String classification and packing assessment
Statistical Analysis	API intelligence
Rich	Terminal output
ReportLab	PDF report generation
JSON	Model assets and structured reports
Pytest	Automated testing

AISA uses lightweight model implementations and local model assets rather than depending on large neural networks or external inference services.

⸻

Project Structure

AISA/
│
├── cli/
│   ├── reporting.py
│   ├── visualizer.py
│   └── ...
│
├── core/
│   ├── workflow.py
│   ├── api_analysis.py
│   └── ...
│
├── data/
│   └── ...
│
├── models/
│   ├── string_model_weights.json
│   ├── packing_model.json
│   ├── api_frequency_model.json
│   └── ...
│
├── training/
│   └── ...
│
├── tests/
│   └── ...
│
├── installer/
│
├── samples/
│
├── reports/
│
├── main.py
├── train.py
├── aisa_version.py
├── pyproject.toml
├── requirements.txt
└── README.md

⸻

Installation

Requirements

* Python 3.9 or newer.
* Windows PE executable samples for analysis.
* Required Python dependencies.
* UPX for the supported UPX unpacking workflow.

1. Clone the repository

git clone https://github.com/airfawn/Artificial_Intelligence_Static_analyser-AISA-.git
cd Artificial_Intelligence_Static_analyser-AISA-

2. Create a virtual environment

Windows:

python -m venv .venv
.venv\Scripts\activate

Linux / macOS:

python3 -m venv .venv
source .venv/bin/activate

3. Install dependencies

pip install -r requirements.txt

Alternatively, install AISA in editable mode to access its command-line entry point:

pip install -e .

4. Verify installation

python main.py --version

Or, if installed through the editable package:

aisa --version

⸻

Usage

AISA provides a command-line interface for analysing PE executables.

Basic Analysis

python main.py samples/sample.exe

This runs the standard analysis workflow and generates a PDF report by default.

Packing-Only Analysis

python main.py --packing samples/sample.exe

This performs packing assessment without running the complete extraction workflow.

Collection-Only Mode

python main.py --collect-only true samples/sample.exe

Runs data collection without the additional offline API analysis stage.

Generate a JSON Report

python main.py --format json samples/sample.exe

Generate a Text Report

python main.py --format text samples/sample.exe

Specify an Output Location

python main.py samples/sample.exe --save reports/analysis.json

When using --save without an explicit format, JSON is used.

Analyse an Existing Report

python main.py --analyze-report reports/analysis.json --analysis-output reports/enriched-analysis.json

For the complete list of available arguments:

python main.py --help

⸻

Reporting

AISA supports three report formats:

Format	Description
PDF	Human-readable analysis report
JSON	Structured analysis data
TXT	Plain-text report

Reports are intended to make findings easier to inspect, compare and use during further investigation.

The analysis output should be interpreted as a collection of indicators and supporting evidence rather than a definitive malware classification.

⸻

Limitations

AISA is an experimental static analysis project and has several limitations.

* Static analysis cannot reliably establish what an executable will do during runtime.
* Packed or obfuscated executables may conceal relevant indicators.
* Automatic unpacking support is currently limited to supported workflows, including UPX.
* String classification can produce false positives and false negatives.
* Packing assessment is experimental.
* API analysis relies on corpus statistics and curated patterns, which can inherit biases from their underlying data.
* Imported APIs do not prove that corresponding functions are executed.
* Model performance should not be assumed without independent evaluation against appropriately labelled datasets.

AISA is not intended to replace established antivirus products, sandbox environments or professional malware-analysis platforms.

⸻

Development Goals

Potential areas for further development include:

* Expanded packer identification and unpacking support.
* Independent evaluation of the machine learning models.
* Improved statistical analysis and corpus coverage.
* YARA rule integration.
* Enhanced analyst-oriented reporting.
* Additional PE metadata analysis.
* Improved detection of obfuscation techniques.
* Expanded automated and integration testing.

⸻

Disclaimer

AISA is intended for educational, research and defensive cybersecurity purposes.

It is an experimental static analysis tool designed to assist investigations. Its findings should not be interpreted as definitive proof that a file is malicious or benign.

Analyse suspicious samples only within an appropriately isolated environment.

⸻

Author

Adithya V

Interested in Cybersecurity, Malware Analysis, Reverse Engineering and Machine Learning.

GitHub: @airfawn

⸻

Built as an exploration of lightweight machine learning and statistical techniques for offline malware analysis.
