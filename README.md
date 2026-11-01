# Breadcrumbss

Breadcrumbss processes completed Wireshark PCAP/PCAPNG segments. It extracts unique source and destination IPs with capture context, optionally looks up public IP registration data via RDAP, and writes timestamped JSON and CSV reports. It does not alter captures.

## Requirements and setup

- Python 3.11 or newer.
- Wireshark's TShark command line program. Confirm it works with: tshark --version
- No Python package dependencies beyond the standard library. From this folder, install with: python -m pip install -e .

If TShark is not on PATH, pass --tshark with its full executable path. On Windows it is commonly installed under Program Files\Wireshark. RDAP requires network access but no API key. VirusTotal IP report lookups are also available as an opt-in provider.

## Commands

Run options after the command name:

    breadcrumbss file path/to/capture.pcapng --dry-run
    breadcrumbss folder path/to/completed-captures --output-dir path/to/results
    breadcrumbss watch path/to/rotating-captures --output-dir path/to/results --provider rdap
    breadcrumbss file path/to/capture.pcap --config config.toml
    breadcrumbss --version

## VirusTotal research lookups

The local capture analysis remains the default. Preview the exact eligible IPs
without loading a key or making an external request:

    breadcrumbss folder C:\PacketCaptures --config config.toml --preview

The preview lists public IPs and each capture's SHA-256 hash. Review the IPs
before approving them. Repeat `--approve-ip` for each exact address to query:

    breadcrumbss folder C:\PacketCaptures --config config.toml --provider virustotal --approve-ip 8.8.8.8

For unattended watch mode, `--approve-all-public` is an explicit policy that
authorizes every public IP found in future completed segments:

    breadcrumbss watch C:\PacketCaptures --config config.toml --provider virustotal --approve-all-public

`--provider virustotal` alone refuses to run. Choose either `--approve-ip` or
`--approve-all-public`; they cannot be combined. In exact-IP mode, public
addresses without approval are marked `not_approved` in the report. Non-public
addresses are excluded in either mode, even with `--include-nonpublic`. Add
`--dry-run` to test the selection without sending requests. VirusTotal receives
only eligible IPs under the selected policy, never captures or packet contents. A
lookup may add an IP to VirusTotal's community dataset, so do not query
sensitive indicators. Reputation is context, not proof that a connection was
malicious.

On Windows, store the key as a DPAPI-encrypted SecureString at
`.secrets/virustotal-api-key.dpapi`, protected for the current Windows user.
Alternatively, set `BREADCRUMBSS_VIRUSTOTAL_API_KEY` in the process environment.
The environment variable takes precedence. Never put a key in `config.toml`,
the command line, reports, or version control. `.secrets/` is ignored.

Successful and empty VirusTotal results are cached separately by IP in the
report state database for `cache_hours` (24 hours by default). A usage database
at `.secrets/virustotal-usage.sqlite3` tracks requests across runs and output
directories. Breadcrumbss enforces at most 4 requests in a rolling 60-second
window and 500 in a UTC day. It waits for a minute slot, stops sending on a
daily limit or HTTP 429, and records remaining addresses as unqueried. Failed
requests are not cached. Use one project copy for all VirusTotal runs with a
given API key so its local usage counter remains shared.

The Community API is for noncommercial use. Review VirusTotal's current terms
and quotas at https://docs.virustotal.com/reference/public-vs-premium-api and
its IP report guidance at https://docs.virustotal.com/reference/ip-info.

To run without installation from this source tree, set PYTHONPATH to src and use python -m breadcrumbss with the same arguments. See config.example.toml for defaults. Command options override the config file. --force creates another report for an already processed capture; cached lookup results may still be reused.

## Wireshark capture setup

In Wireshark Capture Options, choose a named output file, enable multiple files, and switch to a new file every few minutes or at a size limit. Point Breadcrumbss watch mode at that folder. The Wireshark guide describes these file modes: https://www.wireshark.org/docs/wsug_html_chunked/ChapterCapture.html

Watch mode only processes a file after a newer segment exists and the older file's size and modification time have stayed unchanged for stable_seconds. This avoids reading the segment currently being written. The final segment remains unprocessed until a newer segment appears; after capture stops, process it with the file command. If you manually copy files into a watch folder, copy to a temporary extension and rename to .pcap/.pcapng after the copy finishes.

Use continuous segmented capture when every segment matters. Wireshark ring buffers overwrite old segments. Breadcrumbss reports a sequence-number gap when the filename pattern makes one visible, and reports when a previously observed file disappears. It cannot reconstruct overwritten captures or detect every missed segment.

## Reports and state

Each completed capture gets a timestamped folder in output_dir containing timestamped JSON, CSV, and HTML reports. Open the HTML file in a browser for a self-contained summary and readable IP tables; it uses no scripts or external assets. JSON contains full per-IP details and provider results. CSV has one row per IP, including first/last packet time, first/last frame, packet count, directions, protocols, ports, capture hash, provider statuses, and compact provider JSON. Running breadcrumbss again on an already completed capture adds any missing HTML file from its saved JSON without repeating provider lookups.

The output directory also contains breadcrumbss-state.sqlite3. This tracks completed capture hashes and caches successful or empty provider responses. It is required for restart-safe deduplication. A failed provider lookup is recorded in that report but is not cached, so a later run can retry it. To retry an already completed capture, pass --force. The report set is built in a hidden staging folder, then the folder is renamed into place as one unit. An interrupted write leaves no completed report folder.

The tool computes the capture hash before and after parsing and rejects a file that changed during processing. A capture-level failure does not mark the file complete. Different provider or privacy settings create a different processing profile, so a dry-run does not block a later RDAP run.

## Privacy and interpretation

No provider is selected by default. --dry-run prevents all lookups. --provider rdap first downloads IANA's RDAP bootstrap registry and then sends each eligible IP to the authoritative registry's HTTPS RDAP endpoint. It sends IP addresses only, never packet contents or capture files. Non-public addresses are excluded by default; --include-nonpublic explicitly changes that policy for RDAP, never for VirusTotal.

RDAP describes registered network resources. It does not identify a person behind a connection. Results can change; each response records lookup time and source. The CSV/JSON and state database can contain sensitive network metadata, so store them accordingly.

## Adding an API-key provider

The Provider class in providers.py defines the lookup interface. A future provider should read its key from an environment variable, send only the IP address, and return the same status, looked_up_at, source, and data fields as RDAPProvider. Register its name in the Processor provider map and in the CLI's accepted provider names before adding it to a config file. For example, an implemented provider named exampleintel could use EXAMPLEINTEL_API_KEY and then be selected with providers = ["exampleintel"]. This is an extension pattern, not an active provider in this release.

## Limits

The initial version keeps one summary row per unique IP in memory per capture. Very large captures with many unique addresses may need a disk-backed aggregator. Watch mode assumes Wireshark's rotating files have sequence or timestamp names and a newer file is created after rotation. It uses polling, not filesystem notifications. Current RDAP handling uses IANA's authoritative bootstrap data, with a simple per-provider request pace and no automatic retries after rate limiting.

The RDAP bootstrap behavior follows RFC 9224: https://www.rfc-editor.org/rfc/rfc9224.html


## Legacy implementation

The Rust implementation and Windows launchers remain for reference. The Python CLI documented above is the current capture-processing workflow.

## Tests

Run the offline test suite from the repository root:

    python -m unittest discover -s tests -v
