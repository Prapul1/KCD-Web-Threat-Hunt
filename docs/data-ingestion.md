# 🚚 Data Ingestion — Why a Universal Forwarder Was Used

## The problem

The source Sysmon export, `KCD.csv-2026-4-8 14.52.1.csv`, was large enough that it could **not be uploaded directly through the Splunk Cloud "Add Data" web UI**. Browser-based upload in Splunk Cloud is meant for small/one-off files — large CSVs either time out mid-upload or get rejected outright.

## The fix

Instead of the UI upload path, ingestion was done with a **Splunk Universal Forwarder (UF)**:

1. Installed the Universal Forwarder on the machine holding the CSV export.
2. Deployed the Splunk Cloud-provided forwarder credentials / receiving configuration (the app package that points the UF at the Cloud stack's indexers).
3. Configured a monitor stanza in `inputs.conf` pointing at the CSV file/folder, e.g.:

   ```ini
   [monitor://G:\KCD.csv-2026-4-8 14.52.1.csv]
   disabled = false
   index = main
   sourcetype = csv
   ```

4. Restarted the forwarder so it began streaming the file into `index=main` with `sourcetype=csv`.
5. Confirmed complete ingestion in Splunk before starting the hunt:

   ```spl
   index="main" source="G:\\KCD.csv-2026-4-8 14.52.1.csv"
   | stats count
   ```

## Why this matters for the writeup

Every SPL query in this repo references the exact monitored path:

```
source="G:\\KCD.csv-2026-4-8 14.52.1.csv"
```

That's the literal path from the forwarder's `inputs.conf` stanza — not a filename chosen during a web upload. If you're reproducing this hunt against your own export, either:

- match that same monitor path in your own UF config, or
- adjust the `source=` value in every query in [`spl-queries/all-queries.spl`](../spl-queries/all-queries.spl) to match how you ingested the file (UF monitor path, HEC source, or Add Data upload filename).

## General takeaway

For any one-off dataset (CSV/log dump) that's too large for the Splunk Cloud web upload limit, prefer:

- **Universal Forwarder** (what was used here) — good for a single host with a file already sitting on disk.
- **HTTP Event Collector (HEC)** — good for scripted/bulk ingestion from a script or pipeline.

Both bypass the browser upload size ceiling entirely.
