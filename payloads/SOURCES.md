# Prompt Injection Corpus Sources

This document describes the provenance and sources of prompt injection testing payloads used by the llm-api-guard suite.

## Existing Entries
- **Internal**: Generic, widely-published injection patterns authored internally for seed scanning.

## External Maintained Corpora
- **Garak (v0.15.1)**: Imported from Garak probes for jailbreak and instruction override tests.
  Used Probe Classes:
  - `garak.probes.dan.Dan_11_0`
  - `garak.probes.dan.STAN`
  - `garak.probes.dan.DUDE`
  - `garak.probes.dan.AntiDAN`
  - `garak.probes.dan.ChatGPT_Developer_Mode_v2`
  - `garak.probes.promptinject.HijackHateHumans`
  - `garak.probes.promptinject.HijackKillHumans`
  - `garak.probes.promptinject.HijackLongPrompt`
