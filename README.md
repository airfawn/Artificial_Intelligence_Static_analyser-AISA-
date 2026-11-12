Artifical intelligence driven Static Analysis(AISA) is a tool that automates static analysis of a file and uses AI model to correlate the collected data from the extraction to label if the file is a malware or if it is clear. It uses the extracted data to find the functionality of the malware, C2 domain and API calls(imports,exports) used by the file to conduct suspicious behaviour

1) Collection of data
Primary job of this program is to collect data from the sample provided, It first checks for Packing, if the file is packed then it does not proceed to collect strings, it unpacks the file using suitable packer and then continues to extract the strings, API calls, domains, download locations. We use an AI model to detect different packing programs this is a ML script trained with existing data, this allows the program to catch packed programs.

2) Analysing of data
We use a RL fine tuned qwen 1.7B model which analyses the collected data from the collector and finds the different possibilities of malwares it can be with confidence and evidence from the collected data to prove its point. 