Artifical intelligence driven Static Analysis(AISA) is a tool that automates static analysis of a file and uses AI model to correlate the collected data from the extraction to label if the file is a malware or if it is clear. It uses the extracted data to find the functionality of the malware, C2 domain and API calls(imports,exports) used by the file to conduct suspicious behaviour

Funtions:

1) Collection of data
Primary job of this program is to collect data from the sample provided, It first checks for Packing, if the file is packed then it does not proceed to collect strings, it unpacks the file using suitable packer and then continues to extract the strings, API calls, domains, download locations. We use an AI model to detect different packing programs this is a ML script trained with existing data, this allows the program to catch packed programs.

By default the program runs only collection of data, the AI model then runs on collected data to find few data which can be flagged as common malware behaviour using data downloaded from <> and the AI is trained on this data and has a offline version saved which it uses to cross reference.

2) Analysing of data
The API calls are analysed by a ML script which uses a offline database of malwares downloaded by CORPUS and is trained on that dataset. It has 2 functions
-> Flag some imports and provide an explanation of which malware uses it most for which functionality
->Flag a group of imports and state where these group of imports are used and what function that group of imports can achieve.

The Mode is under development and the model exists but not fine tuned completely. To enable this mode we run "--collect-only=False" to enable the AI mode to analyse the data and provide a fixed report.

3) Report Generation

This is an extension of the collection of data where the data is presented in a report format(.pdf) which will be acceptable to send to superiors.

USAGE:
