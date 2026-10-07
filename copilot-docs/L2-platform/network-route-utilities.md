# Network Route Utilities


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/network-route-utilities.content.md` before answering — that companion holds the per-file
> implementation detail. For a high-level overview this compact doc is the
> right altitude; escalate to the companion (then targeted source) only
> when the question turns on a specific symbol or step.
> The companion concatenates one `## <source/path>.cs` section per file and
> can be large — don't read it whole: `grep_search` it for your target `.cs`
> name to find its `## ` line, `read_file` only that range, and start with
> its *Purpose and Functionality* sub-section.
<!-- TIER2-POINTER:END -->
**TL;DR:** `RouteEntry` models one Linux IPv4 route using the hexadecimal network-byte-order values exposed by the route table. It converts those values to dotted-quad addresses and provides stable JSON, display, and debug representations.

<!-- TIER2-POINTER:BEGIN -->
> For implementation detail, read the companion [tier-2 source summary](../../intermediate-docs/L2-platform/network-route-utilities.content.md) surgically: locate the relevant source-file section, then inspect its purpose and key components.
<!-- TIER2-POINTER:END -->

## Why

Linux route-table data represents destination, gateway, and mask addresses as eight-character hexadecimal strings in network byte order. Agent diagnostics need those low-level values converted consistently into readable IPv4 addresses while retaining the original route attributes.

`RouteEntry` centralizes that conversion and formatting so callers do not independently reinterpret byte order, numeric flags, or metrics.

## What

### Route model

| Field | Stored form | Meaning |
|---|---|---|
| `interface` | String | Network interface associated with the route. |
| `destination` | Eight-character hexadecimal string | IPv4 route destination in network byte order. |
| `gateway` | Eight-character hexadecimal string | IPv4 gateway in network byte order. |
| `mask` | Eight-character hexadecimal string | IPv4 netmask in network byte order. |
| `flags` | Integer parsed from hexadecimal input | Route flags. |
| `metric` | Integer parsed from decimal input | Route priority metric. |

Construction normalizes `flags` and `metric` immediately while preserving the three hexadecimal address values for later conversion.

### Address conversion

`RouteEntry._net_hex_to_dotted_quad` requires exactly eight hexadecimal characters. It reads the octets from the end of the string toward the beginning, converts each pair to decimal, and joins the results as an IPv4 dotted quad.

`destination_quad`, `gateway_quad`, and `mask_quad` apply this conversion to their corresponding stored fields. Invalid length or non-hexadecimal content raises an exception rather than producing a partial address.

### Representations

| Method | Output intent |
|---|---|
| `to_json` | JSON-shaped diagnostic record with dotted-quad addresses, hexadecimal flags, and metric. |
| `__str__` | Human-readable tab-separated route details. |
| `__repr__` | Constructor-like diagnostic form that retains the original hexadecimal address values. |

These methods format a route for diagnostics; they do not query, add, remove, or select operating-system routes.

## How

### Using a route entry

1. Create `RouteEntry` from an already parsed route-table row.
2. Pass destination, gateway, and mask exactly as eight-character network-order hexadecimal strings.
3. Use the `*_quad` methods when consumers need readable IPv4 values.
4. Use `to_json` or `str` for diagnostic output and `repr` when the original encoded values are important.

### Change guidance

- Preserve the reverse-octet conversion order; Linux route-table hexadecimal values are not in dotted-quad display order.
- Keep strict eight-character validation so malformed route data fails explicitly.
- Preserve constructor normalization of hexadecimal flags and decimal metrics.
- Keep output field names and flag formatting stable when diagnostic consumers may parse the serialized form.
- Do not extend this value object with route-table mutation or policy decisions; those belong to higher-level networking components.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Route value model and normalization | `azurelinuxagent/common/utils/networkutil.py` | `RouteEntry`; `RouteEntry.__init__` |
| Hexadecimal IPv4 conversion | `azurelinuxagent/common/utils/networkutil.py` | `RouteEntry._net_hex_to_dotted_quad`; `RouteEntry.destination_quad`; `RouteEntry.gateway_quad`; `RouteEntry.mask_quad` |
| Diagnostic serialization | `azurelinuxagent/common/utils/networkutil.py` | `RouteEntry.to_json`; `RouteEntry.__str__`; `RouteEntry.__repr__` |
