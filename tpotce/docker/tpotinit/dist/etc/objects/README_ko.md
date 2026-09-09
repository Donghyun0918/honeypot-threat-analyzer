# Korean-translated Kibana export

`kibana_export_ko.ndjson` is a parallel, Korean-localized version of
`kibana_export.ndjson`. It preserves all 303 upstream saved objects
(dashboards, visualizations, lenses, index patterns, tags, queries) and
adds 12 new objects for the optional ML / LLM analyzer dashboards.

## What is translated

User-facing label fields only:

- `attributes.title`
- `attributes.description`
- `attributes.name`

Everything else is byte-identical to upstream:

- Object IDs, references, types, versions
- Stringified JSON blobs (`panelsJSON`, `visState`, `searchSourceJSON`,
  `fieldAttrs`, …)
- Field references (so visualizations keep working)

## Translation strategy

Conservative pass-1 translator (`integration-tests/translate_kibana.py`):

- Multi-word phrases are matched verbatim, longest-first.
- Single English words use Python regex word boundaries (`\b`) so e.g.
  `Attack` does **not** eat `Attacker`.
- Product names (`Cowrie`, `Suricata`, `Heralding`, `Tanner`,
  `CitrixHoneypot`, `Sentrypeer`, etc.) are left untouched.

To re-run after a T-Pot upstream update:

```bash
python3 integration-tests/translate_kibana.py
```

## How to use

Replace the default Kibana export:

```bash
cp tpot-fork/docker/tpotinit/dist/etc/objects/kibana_export_ko.ndjson \
   tpot-fork/docker/tpotinit/dist/etc/objects/kibana_export.ndjson
```

Or import on a running T-Pot:

```bash
curl -k -u "<user>:<pw>" -X POST \
  "https://<tpot-host>:64297/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -F "file=@kibana_export_ko.ndjson"
```

Verified clean import on Kibana 9.2.3 (T-Pot 24.04.1) — 315/315 objects,
0 errors.
