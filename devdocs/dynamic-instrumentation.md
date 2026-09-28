# Dynamic instrumentation

Dynamic instrumentation adds internal spans to running processes without restarting
OBI. OBI discovers the process, opens its executable through `/proc`, resolves
function symbols, and owns the resulting uprobe links. Configure it separately
from application discovery and log enrichment:

```yaml
dynamic_instrumentation:
  enabled: true
  listen_address: 0.0.0.0:8089
  rules:
    - service:
        - exe_path: "*/checkout"
      spans:
        - name: checkout.place_order
          on:
            function_span: "main.(*Checkout).PlaceOrder"
```

Enable the feature at startup, even if `rules` is initially empty. A nonempty
`rules` list or `listen_address` also enables it. Use OBI's usual trace exporter
configuration to send these spans. Dynamic selection respects the existing
application discovery exclusions.

Each `service` entry uses OBI's glob discovery criteria. Entries are alternatives;
fields within an entry must all match. Examples include `target_pids: [1234]`
(host PIDs), `exe_path: "*/checkout"`, `open_ports: "8080-8089"`, `cmd_args`,
`languages`, `k8s_namespace`, `k8s_pod_name`, `k8s_service_name`, and pod label or
annotation selectors. Kubernetes selectors require Kubernetes discovery to be
enabled. A Kubernetes Service matches pods in its namespace through its selector,
including headless Services. Selectorless Services do not identify processes.

Function patterns support `*`, `?`, character classes, and alternatives such as
`main.{read,write}`. An exact symbol wins over glob expansion, so a Go pointer
receiver such as `main.(*Checkout).PlaceOrder` works literally. Inlined functions
without a separately emitted body cannot be probed. Go's runtime function table
also permits name resolution in stripped executables.

Go handler factories can be inlined while their returned closures remain as
symbols such as `std.Setup.HTTPHandler.func1`. To instrument those closures, use
`*HTTPHandler*`; `*HTTPHandler` only matches symbols ending in `HTTPHandler`.

## API

The HTTP listener is optional and does not require authentication. Set
`listen_address: 0.0.0.0:8089` to accept connections on all IPv4 interfaces, or
`listen_address: "[::]:8089"` for IPv6. External controllers use OBI's reachable
address in place of `127.0.0.1` in the examples below.
In a DaemonSet, send requests to OBI on the node hosting the selected workload.
OBI does not forward rules between nodes.

Create or replace a named rule:

```sh
curl -X PUT http://127.0.0.1:8089/v1/dynamic-instrumentation/rules/checkout \
  -H 'Content-Type: application/json' \
  -d '{
    "service": [{"k8s_namespace": "shop", "k8s_service_name": "checkout"}],
    "spans": [{"name": "checkout.call", "on": {"function_span": "main.*Order*"}}]
  }'
```

`POST /v1/dynamic-instrumentation/probes` accepts the same body and returns a
stable rule ID derived from it. Rules remain active for processes discovered
later, until removed or OBI exits. API rules are held in memory.

The response contains `id` and a `probes` list with the host PID, resolved function,
span name, OpenTelemetry service name and namespace, status, and any error.
`attached` means the kernel accepted the attachment; it does not guarantee that
the function has executed or that an exporter delivered its spans.

| HTTP status | Meaning |
| --- | --- |
| 200 | All reported probes attached. |
| 202 | Discovery is still pending after `request_timeout`; the rule remains active. |
| 207 | At least one resolved target failed; inspect each result's `error`. |
| 400 / 422 | Malformed request or invalid criteria. |

List the probes managed by this API and file rules, optionally filtering with a
URL-encoded JSON `service` array:

```sh
curl --get http://127.0.0.1:8089/v1/dynamic-instrumentation/probes \
  --data-urlencode 'service=[{"target_pids":[1234]}]'
```

List the available function symbols in the main executable of each matching
process, using the same `service` selectors:

```sh
curl --get http://127.0.0.1:8089/v1/dynamic-instrumentation/symbols \
  --data-urlencode 'service=[{"open_ports":"8081","k8s_namespace":"froggies-demo"}]'
```

The `service` array is required. This read-only endpoint works for processes OBI
has discovered before any instrumentation rule or probe is attached. It returns
all resolvable function names, including Go runtime symbols in stripped binaries,
grouped by host PID and sorted by PID and symbol name:

```json
{
  "processes": [
    {
      "pid": 1234,
      "service_name": "testserver",
      "service_namespace": "froggies-demo",
      "symbols": ["main.HTTPHandler", "main.echo", "main.echoAsync"]
    }
  ]
}
```

Use a returned name directly in `on.function_span` or `on.function_noret`.
Service name and namespace are empty until OBI assigns the process a service.
HTTP 200 with `{"processes":[]}` means no discovered process matches the filter.
Invalid or missing selectors return HTTP 400. If a process exits, changes its
executable, or its symbols cannot be read, HTTP 207 retains successful results
and includes an `error` and an empty `symbols` array for each failed process.
Attachment success is reported separately by the probes API.

Remove a specific function, or a glob of functions, from matching processes:

```sh
curl -X DELETE http://127.0.0.1:8089/v1/dynamic-instrumentation/probes \
  -H 'Content-Type: application/json' \
  -d '{"service":[{"target_pids":[1234]}],"function":"main.*Order*"}'
```

This suppresses those functions for those process instances until a matching API
rule is applied again or an updated file ruleset requests them. Remove an entire API rule with
`DELETE /v1/dynamic-instrumentation/rules/checkout`. A probe shared with another
rule remains attached until all owners release it. Listing uses OBI's attachment
metadata and excludes its predefined language and protocol probes.

The earlier prober API remains available at `/v1/probes`: PUT accepts `generation`,
`pid`, ELF file `offset`, `span_name`, and optional `ttl_seconds`. GET lists these
legacy probes and DELETE removes one by ID. These are entry-only marker spans;
the named-function API above resolves addresses and return sites inside OBI.

## Reload and limits

When OBI is started with a configuration file, it polls that path and reconciles
changes to `dynamic_instrumentation.rules`. Replacing the file atomically or
updating a ConfigMap symlink works. Invalid updates preserve the previous rules.
Symbol resolution and attachment failures are logged with the rule ID, PID,
function pattern or symbol, and error. Other valid probes remain attached.
The GET probes endpoint lists successful attachments only.
API rules survive file reloads. Other configuration changes, including listener
and cache settings, take effect at startup only. Configuration read from standard
input has no file to watch.

| Option | Default | Meaning |
| --- | --- | --- |
| `watch_interval` | `1s` | Configuration polling interval. |
| `request_timeout` | `10s` | Maximum wait for asynchronous discovery in an API response. |
| `ttl` | `5m` | Expiry of incomplete span pairs and inherited goroutine context, not attached probes. |
| `max_probes` | `1024` | Maximum concurrently managed PID/function probes. |
| `symbol_cache_entries` | `32` | Maximum executable identities in each tracer's LRU. |
| `symbol_cache_bytes` | `67108864` | Total estimated symbol storage per tracer's LRU. |
| `max_cached_binary_bytes` | `8388608` | Maximum estimated symbol storage for one executable. |

Cache identity includes device, inode, size, and modification time. The per-binary
limit measures symbol storage, not the executable's file size. Executables over
the limit are parsed for each request and are not retained. Setting any cache
limit to zero disables caching. Symbol listing reuses a registered tracer's cache;
processes without a tracer share a separate LRU with the same configured limits.
Removing probes releases their links, decoding
metadata, and reusable BPF specification slots. Process exit removes its probes.

Internal metrics expose `obi.dynamic.probes` (Prometheus: `obi_dynamic_probes`),
with `service.name`, `service.namespace`, `process.pid`, and `code.function.name`.
Each active PID/function contributes one; detached probes disappear.

## Go spans and values

Go entry and return-site uprobes pair by goroutine, so scheduling onto another
OS thread does not split a call. Nested and recursive dynamic calls form a span
stack. OBI's shared Go trace map supplies the current automatic server span.
Read-only probes on the standard Go OpenTelemetry SDK's `tracer.Start` return
and `recordingSpan.End` track SDK span context for scoped calls on that goroutine.
An SDK-instrumented application can therefore receive additional OBI spans even
when its existing spans are already exported by its SDK.

Dynamic probe spans bypass the duplicate-trace suppression controlled by
`discovery.exclude_otel_instrumented_services`. OBI continues suppressing
protocol spans for SDK-instrumented services, which can still appear in the
`obi.avoided.services` metric. Explicit trace filters, service export settings,
and sampling still apply.

OBI also reads `service.name` and `service.namespace` from the standard Go SDK's
TracerProvider resource when the application starts an SDK span. This works when
the provider was created before OBI attached, and with stripped Go executables.
The learned identity replaces inferred executable/Kubernetes names in OBI
telemetry and the dynamic-probe API; explicit OBI service settings take precedence.
The first observed SDK identity is used for the process, including applications
with multiple providers. Until an SDK span starts, OBI uses its existing metadata.
This metadata discovery also works without dynamic instrumentation enabled.
Resource scanning is limited to 128 attributes and 255 bytes per service string.

When a Go function launches a goroutine, OBI snapshots its active dynamic span or
SDK/server context at creation. Dynamic calls in the child inherit that parent,
even if the creating function returns before the child runs. Nested goroutine
creation preserves this ancestry. A newer SDK span activated in the child takes
precedence. Inherited context is bounded to 30,000 goroutines, expires after
`ttl`, and is cleared when the goroutine exits or is reused.

For supported standard Go SDKs, spans started inside a dynamic call can also
become children of that dynamic span: `SDK server → dynamic span → SDK client`.
OBI uses `bpf_probe_write_user` at `tracer.newRecordingSpan` return to update the
new span's private parent ID before span processors run. It does not overwrite
the caller's shared `context.Context`. The SDK exports its own child span;
OBI's duplicate protocol spans remain suppressed after SDK export detection.
The application must create SDK client spans and pass the server context, for
example with `otelhttp.NewTransport` and `http.NewRequestWithContext`.

Parent rewriting requires `CAP_SYS_ADMIN`, a kernel permitting
`bpf_probe_write_user`, and validated module checksums and field offsets.
Currently reviewed SDK and trace module versions are 1.43.0 and 1.46.0 on
amd64/arm64; replaced, unversioned, and unreviewed modules are skipped.
Without write support, dynamic spans still inherit SDK parents, but SDK children
retain their original parents. Explicit new roots, remote or unrelated parents,
and children of a newer SDK span are preserved. The SDK sampler and the context
argument passed to processors still see the original parent context.

Context handed to an already-running worker goroutine without an observable
activation, non-recording SDK spans, custom SDK implementations, and spans ended
out of nesting order can lack an accurate parent. When no parent context is
available, OBI creates a root trace for the dynamic call.

For Go register-ABI functions, OBI attempts automatic scalar and string capture
from DWARF signatures, or retained runtime method metadata in stripped binaries.
Attributes are named `arg0`, `arg1`, and `return0`, `return1`, etc. Values are
encoded as strings. Capture is bounded to 12 inputs and 12 results, and strings
are truncated to 127 bytes. Empty strings are supported. Supported pointer
receiver metadata can also expose exported scalar/string fields of struct
arguments. Capture can include sensitive application data; scope rules accordingly.

Floating-point registers, stack-spilled arguments, unsupported composite
signatures, generic ABI dictionary parameters, and signatures removed by stripping
are not reliably available from these probes. Unsupported signatures retain timing
instrumentation without automatic values. Panics, tail calls without a return
site, and lost ring-buffer events can prevent a pair from completing; stale starts
expire after `ttl`. `function_noret` emits an entry-only, zero-duration span instead.

The POC's USDT targets also remain available: `usdt_noret: "provider:event"` emits
a marker, and `usdt_span: "provider:operation"` pairs `operation_start` and
`operation_end` using their first integer argument as the correlation key. Explicit
`attrs` and USDT string `match` filters use the original POC schema.

Dynamic attachments require Linux amd64 or arm64 and attach-cookie support
(normally kernel 5.15 or newer). An unsupported kernel reports an attachment error;
OBI's existing instrumentation retains its original kernel requirements.
