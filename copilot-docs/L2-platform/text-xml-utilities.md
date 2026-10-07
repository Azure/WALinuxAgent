# Text and XML Utilities


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/text-xml-utilities.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `textutil.py` centralizes XML DOM access, byte/text compatibility, binary formatting, configuration-line mutation, encoding, redaction, and small parsing helpers. Its functions keep protocol and platform callers consistent across Python versions without hiding malformed input or parse failures.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/text-xml-utilities.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

The agent exchanges XML and JSON protocol documents, handles binary network data, edits Linux configuration text, and emits diagnostics on varied Python runtimes. A shared utility layer prevents each caller from inventing different rules for namespace lookup, missing nodes, byte conversion, BOM removal, exception formatting, and sensitive URL handling.

These helpers are intentionally small and mostly policy-free. Parsing, decoding, and invalid-value errors generally remain visible so the subsystem with operational context can decide whether to reject, retry, or report the input.

## What

### XML DOM access

| Operation | Contract |
|---|---|
| `parse_doc` | UTF-8 encodes text before parsing it with `minidom.parseString`, preserving Python 2 compatibility. |
| `findall` | Returns all descendant elements by tag, optionally using an XML namespace; a missing root yields an empty list. |
| `find` | Returns the first matching descendant or `None`. |
| `gettext` | Returns the first direct text child's data or `None`. |
| `gettextxml` | Returns the first direct text child's serialized XML or `None`. |
| `findtext` | Composes `find` and `gettext` for first-match text lookup. |
| `getattrib` / `hasattrib` | Read or test an attribute while handling a missing node. A present node with a missing attribute returns an empty string from `getattrib`. |

Lookups are descendant-based because they use DOM `getElementsByTagName` APIs; they are not limited to immediate children. Text access similarly returns only the first direct text node and does not concatenate mixed content.

### Binary and diagnostic text

- `unpack`, `unpack_little_endian`, and `unpack_big_endian` convert byte ranges to integers.
- `str_to_ord` and `compare_bytes` normalize indexing differences between byte strings and integer arrays.
- `hex_dump2`, `hex_dump3`, and `hex_dump` produce compact or offset-and-ASCII diagnostic representations.
- `int_to_ip4_addr`, `hexstr_to_bytearray`, and `swap_hexstring` convert common network and hexadecimal forms.
- `is_in_range` and `is_printable` support dump formatting; printable output is deliberately limited to ASCII letters and digits.

### Text, encoding, and serialization

- `replace_non_ascii` removes or replaces characters whose ordinal is greater than 128.
- `remove_bom` strips the first three high-valued bytes used as a UTF-8 BOM heuristic.
- `get_bytes_from_pem` removes PEM delimiter lines and joins the encoded payload.
- `compress` returns zlib-compressed, Base64-encoded text suitable for compact log fields.
- `b64encode` and `b64decode` normalize Base64 text behavior across Python versions.
- `safe_shlex_split` adapts shell-like tokenization for Python 2.6.
- `parse_json` trims trailing whitespace and null bytes, returns `None` for empty input, and otherwise delegates validation to `json.loads`.
- `str_to_encoded_ustr` converts values to the repository's Unicode type, decoding bytes with the requested encoding.

### Configuration and reporting helpers

`set_ssh_config` updates the first matching SSH option outside conditional `Match` blocks, or inserts a missing option before the active conditional block. `set_ini_config` replaces the last exact `name=` entry or inserts a quoted value near the end of the supplied line list. Both mutate the provided list.

`format_memory_value` converts byte, kilobyte, megabyte, or gigabyte quantities to integer bytes and rejects unsupported units. `format_exception` produces the exception text plus its traceback when one is available.

`redact_sas_token` replaces recognized Azure SAS query parameters in HTTPS URLs with `<redacted>` before messages reach logs or events. `is_str_none_or_whitespace` and `is_str_empty` provide the shared empty-input checks used by parsers and normalizers.

## How

### Usage guidance

1. Parse protocol XML with `parse_doc`, then use `find` or `findall` with the document's namespace contract.
2. Check optional nodes before assuming text exists; `find`, `gettext`, and `findtext` may return `None`.
3. Choose binary helpers with explicit offset, length, and endianness; they do not perform bounds validation for callers.
4. Normalize bytes at the boundary with `str_to_encoded_ustr`, `remove_bom`, or Base64 helpers rather than mixing byte and text types downstream.
5. Redact SAS-bearing URLs before logging; do not use generic string replacement that can leave credential parameters behind.
6. Let XML, JSON, Base64, numeric, and decoding failures propagate unless the caller owns a documented recovery path.

### Change guidance

- Preserve the `None`, empty-list, and empty-string distinctions in XML helpers; protocol consumers can depend on them.
- Keep namespace-aware and namespace-free lookups behaviorally aligned.
- Treat `gettext` as first-direct-text-node access; changing it to aggregate descendants can alter protocol values.
- Maintain Python compatibility in byte indexing, Unicode conversion, shell splitting, Base64, and traceback formatting.
- Keep configuration edits outside SSH conditional blocks and preserve in-place mutation semantics.
- Update SAS redaction tests whenever supported token shapes or logged URL formats change.
- Prefer focused helpers over adding subsystem policy to this module.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| XML parsing and lookup | `azurelinuxagent/common/utils/textutil.py` | `parse_doc`; `findall`; `find`; `gettext`; `gettextxml`; `findtext`; `getattrib`; `hasattrib` |
| Binary unpacking and dumps | `azurelinuxagent/common/utils/textutil.py` | `unpack`; `unpack_little_endian`; `unpack_big_endian`; `hex_dump`; `hex_dump2`; `hex_dump3`; `compare_bytes` |
| Network and hexadecimal conversion | `azurelinuxagent/common/utils/textutil.py` | `int_to_ip4_addr`; `hexstr_to_bytearray`; `swap_hexstring`; `str_to_ord` |
| Configuration mutation | `azurelinuxagent/common/utils/textutil.py` | `set_ssh_config`; `set_ini_config` |
| Encoding and serialization | `azurelinuxagent/common/utils/textutil.py` | `remove_bom`; `compress`; `b64encode`; `b64decode`; `parse_json`; `str_to_encoded_ustr` |
| Validation and diagnostics | `azurelinuxagent/common/utils/textutil.py` | `is_str_none_or_whitespace`; `is_str_empty`; `format_memory_value`; `format_exception`; `redact_sas_token` |
| Cross-version Unicode type | `azurelinuxagent/common/future.py` | `ustr` |

## Related Components

- [Runtime Compatibility Helpers](runtime-compatibility-helpers.md) — defines `ustr`, the cross-version Unicode abstraction used by conversion and exception formatting.
- [File I/O Utilities](file-io-utilities.md) — applies `remove_bom` before decoding text read from files.
- [Protocol Data Contracts](../L1-conceptual/protocol-data-contracts.md) — protocol models consume the XML and serialization primitives documented here.
