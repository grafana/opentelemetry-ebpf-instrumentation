# Dynamic instrumentation

Dynamic instrumentation adds internal spans to running processes without restarting
OBI. OBI discovers processes and instruments native/Go functions with uprobes.
For Java, its injectable Byte Buddy agent instruments methods with enter/exit advice.
For Node.js, its injected agent wraps exported CommonJS functions and methods.
Configure it separately from application discovery and log enrichment:

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
`attached` means the kernel accepted a uprobe attachment or the Java agent
successfully retransformed the selected methods, or the Node agent wrapped the
selected exports; it does not guarantee that
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

List the available function symbols in each matching process's main executable,
loaded Java methods, or supported Node.js exports, using the same `service` selectors:

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

`obi.dynamic.function.invocations` (Prometheus:
`obi_dynamic_function_invocations_total`) counts entry probe hits for each live
attachment. It starts at zero, counts calls before they return, and excludes
return-probe hits. Counting happens in BPF before event-buffer submission and
span filtering, so sampling, duplicate-span suppression, dropped events, and
unfinished calls do not hide probe activity. For paired USDT probes it counts
the start probe, before argument matching. These are raw probe hits: Go stack
growth can retry a function entry, so the count can exceed logical calls.

The counter carries `process.pid` (the PID visible to OBI), `code.function.name`,
`service.name`, `service.namespace`, `service.instance.id`,
`telemetry.sdk.language`, `host.name`, and available container and Kubernetes
metadata, including pod name/UID, namespace, node, cluster, and workload owners.
It uses the same Kubernetes fields as `target_info`. Metadata is read at
collection time, so late Kubernetes decoration and SDK service names appear
without another function call. Prometheus replaces dots in label names with
underscores. `obi.dynamic.probe.id` identifies the attachment within the OBI
instance; each glob match has its own counter and reattachment gets a new ID.
Address-based probes use their hexadecimal offset as `code.function.name`.

API deletion, config reconciliation, TTL expiry, process exit, and shutdown
remove the BPF counter and the exporter-held metadata. The series disappears
from subsequent collections; data already stored in a backend remains there.

Enable the Prometheus internal exporter, for example:

```yaml
internal_metrics:
  exporter: prometheus
  prometheus:
    port: 6060
    path: /metrics
```

For OTLP use `internal_metrics.exporter: otel` and configure
`otel_metrics_export.endpoint`. OTLP honors the exporter's cumulative or delta
temporality. To inspect hit rates in Prometheus:

```promql
sum by (process_pid, code_function_name, service_name, k8s_pod_name) (
  rate(obi_dynamic_function_invocations_total[1m])
)
```

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

Native/Go dynamic attachments require Linux amd64 or arm64 and attach-cookie support
(normally kernel 5.15 or newer). An unsupported kernel reports an attachment error;
OBI's existing instrumentation retains its original kernel requirements.

## Java methods and values

Enable `javaagent.enabled` and `dynamic_instrumentation` at OBI startup. OBI loads
its Java agent into matching JVMs and uses the same rule, symbols, probes, DELETE,
and file-reload APIs as native/Go instrumentation:

```yaml
javaagent:
  enabled: true
dynamic_instrumentation:
  enabled: true
  listen_address: 0.0.0.0:8089
  rules:
    - service:
        - open_ports: "8080"
          languages: [java]
      spans:
        - name: checkout
          on:
            function_span: "com.example.CheckoutService.*Order"
```

Java symbols use `fully.qualified.Class.method`, including `$` for nested classes.
An attachment covers all overloads of that method name and all loaded definitions
of that class. Each PID/method has one probe entry and invocation counter. The
symbols endpoint lists loaded, modifiable methods; class-load notifications cause
rules to be reconciled as more methods become available. Constructors, native,
abstract, synthetic and lambda methods, JDK classes, and instrumentation libraries
are excluded. Java supports `function_span`; native offsets, USDT targets and
`function_noret` are not Java method targets.

Match the fully qualified method name without parameter types or a JVM descriptor.
For example, these patterns select methods in `com.example.CheckoutService`:

| `function_span` | Matches |
| --- | --- |
| `com.example.CheckoutService.placeOrder` | All `placeOrder` overloads, such as `placeOrder(String)` and `placeOrder(long)`. |
| `com.example.CheckoutService.*Order` | Methods ending in `Order`, such as `placeOrder` and `cancelOrder`. |
| `com.example.CheckoutService.{placeOrder,cancelOrder}` | Both named methods, including their overloads. |
| `com.example.CheckoutService$Worker.run` | The `run` method of the nested `Worker` class. |

To attach an exact method through the API:

```sh
curl -X PUT http://127.0.0.1:8089/v1/dynamic-instrumentation/rules/java-checkout \
  -H 'Content-Type: application/json' \
  -d '{
    "service": [{"open_ports": "8080", "languages": ["java"]}],
    "spans": [{"name": "place-order", "on": {"function_span": "com.example.CheckoutService.placeOrder"}}]
  }'
```

Use the symbols endpoint with the same service criteria to find the actual names
available in your JVM before creating a rule.

Byte Buddy advice runs on entry and on normal or exceptional exit. Java invocation
IDs pair events across virtual-thread carrier changes. Arguments become `arg0`,
`arg1`, etc., and a normal non-void result becomes `return0`. Each value is converted
synchronously using `toString()`; primitives are boxed, null becomes `"null"`, and
throwing conversions become `"<toString failed>"`. Capture is limited to 12
arguments and 127 UTF-8 bytes per value. Calls made by these conversions do not
create recursive dynamic spans. Exceptions produce `exception.message`; the
original exception continues to the caller. Value capture can add overhead and
expose application data, so select methods accordingly.

With an active OpenTelemetry Java SDK or Java-agent span, advice installs a
non-recording span context for the duration of the method. SDK children then
inherit that context: `SDK server → OBI custom method → SDK client`. Exit restores
the previous scope, including when the method throws. OBI exports the custom span
through its existing trace pipeline; the Java SDK exports its own spans. Existing
duplicate-protocol-span suppression continues to apply, while custom spans pass
through. Sampling and explicit user filters still apply. Work scheduled
asynchronously needs the application's or Java agent's normal context propagation;
explicit SDK parents and new roots retain their SDK semantics.

### Async context and sampling behavior

For supported executor and fork/join tasks, the Java agent reports task capture,
start, completion, and cancellation to OBI over ioctl. OBI's eBPF maps associate
the task with the active dynamic span, install that context while the task runs,
and restore the worker's prior context on exit. This carries OBI span parentage;
it does not by itself propagate the Java SDK's `Context` or `Span.current()`, which
continues to depend on application or framework context propagation. Cleanup
removes task state on completion or cancellation. This mechanism has been tested
with executor/fork-join and virtual-thread scenarios, plus one Reactor
`publishOn(Schedulers.parallel())` path; it is not a guarantee for arbitrary
async frameworks or operators.

Dynamic Java spans are diagnostic spans produced by OBI, not SDK spans. In the
tested cases, an SDK sampler that drops its parent span does not prevent OBI from
emitting the dynamic span (with the parent's unsampled trace flag), and
`InstrumentationUtil.suppressInstrumentation` suppresses the Java agent's own
instrumentation without suppressing OBI's dynamic span. This separation is useful
for troubleshooting. The OBI span still uses OBI's own trace pipeline and its
sampling, filters, and export settings; it is not a promise to bypass those
controls. Whether dynamic instrumentation should have any broader exception to
sampling or suppression policy remains a design discussion.

When no SDK context is active, OBI can supply its current server context through
the ioctl buffer. That fallback requires `CAP_SYS_ADMIN` and a kernel permitting
`bpf_probe_write_user`. SDK parenting itself uses Java context scopes and does not
require this helper. If no parent can be obtained, the custom call starts a trace.
Java method instrumentation does not require uprobe attach-cookie support.

The Java agent sends entry, exit and readiness events through ioctl operations
8, 9 and 10. A private loopback control socket carries method lists and
retransformation requests. OBI joins the target network namespace when necessary;
the endpoint and capability token are learned from the kernel event. This does
not change the externally accessible, unauthenticated OBI HTTP API. A new OBI
control session clears stale Java probe registrations before attaching new ones.
If starting the Java agent manually, pass `dynamicInstrumentation=true` in its
agent options. A JVM already running an older OBI agent needs the updated agent.

The method catalog uses a bounded LRU with the existing `symbol_cache_entries`,
`symbol_cache_bytes`, and `max_cached_binary_bytes` options, applied per JVM
catalog. Oversized catalogs are read again instead of retained. One response is
limited to 100,000 method names and 64 MiB of name data. The Java BPF registration
map currently permits 256 method probes, sharing the invocation-counter map with
native/Go probes. Successful deletion removes advice registrations, decoding
metadata and metric series. Calls already executing retain their scope until exit.

For Java regression tests, run `make java-test`. Set
`OBI_TEST_OTEL_AGENT_JAR=/path/to/opentelemetry-javaagent.jar` to additionally run
the Java-agent context test. The live BPF regression requires the normal OBI kernel
permissions, a JDK, and the rebuilt agent:

```sh
OBI_JAVA_AGENT_JAR="$PWD/pkg/internal/java/build/obi-java-agent.jar" \
  go test -tags jvm_live -run '^TestJavaDynamicSpansLive$' -timeout 2m \
  ./pkg/internal/ebpf/generictracer
```

## Node.js functions and values

Enable `nodejs.enabled` and `dynamic_instrumentation` at OBI startup. Node.js 14
or newer is required. OBI injects its Node agent through the existing inspector
injection path. The same service selectors, glob matching, symbols API, probe
listing, deletion, configuration reload, and invocation metrics apply to Node:

```yaml
nodejs:
  enabled: true
dynamic_instrumentation:
  enabled: true
  listen_address: 0.0.0.0:8089
  rules:
    - service:
        - open_ports: "3000"
      spans:
        - name: checkout.place_order
          on:
            function_span: "*/checkout.cjs:exports.placeOrder"
        - name: checkout.worker
          on:
            function_span: "*/checkout.cjs:exports.Worker.prototype.*"
```

The symbol name is the loaded CommonJS module's absolute filename, `:exports`,
and its exported property path. These matchers apply to an application that
exports `placeOrder` and a `Worker` class:

| Pattern | Matches |
| --- | --- |
| `/app/checkout.cjs:exports.placeOrder` | One exported function. |
| `*/checkout.cjs:exports.*Order` | Exported functions ending in `Order`. |
| `*/checkout.cjs:exports.{placeOrder,cancelOrder}` | Either named export. |
| `*/checkout.cjs:exports.Worker.prototype.run` | An exported class's instance method. |
| `*/handler.cjs:exports` | A function assigned directly to `module.exports`. |

Use `/v1/dynamic-instrumentation/symbols` to discover the exact available names.
Patterns expand in OBI against the agent's catalog. New modules appear on the
next catalog refresh, and matching rules reconcile without restarting Node or
OBI. Node targets support `function_span`.

The agent wraps writable or configurable exported functions and methods,
including modules loaded before injection. Calls must go through the wrapped
export or method. Local functions, native ESM exports, generators, constructors,
accessors, application-created proxies, and references copied before attachment
are not instrumented. Frozen export properties are omitted from the catalog.
A local `function work() { ... }` must be exported and called through that export
to be a target. The agent does not rewrite loaded JavaScript source. Worker-thread
isolates are not covered by the main-thread agent.

Synchronous calls retain their result, receiver and thrown error. Native promises
remain asynchronous, and their spans end when they resolve or reject. The wrapper
returns a chained promise; promise object identity changes. Callback-style
functions that return immediately have spans covering the synchronous call only.
Thenables other than native promises are treated as synchronous return values.

Arguments `arg0` through `arg11`, `return0`, and `exception.message` are recorded
as strings using JavaScript conversion, with 127-byte UTF-8 limits. Failed
conversions are omitted. Attribute payloads have a combined 1900-byte limit;
trailing arguments are removed when necessary. Conversion can execute an
application's `toString` method. Explicit string `attrs` can rename argument
slots using the existing dynamic probe schema.

AsyncLocalStorage isolates concurrent calls and maintains nested dynamic scopes
across promises and callbacks. Without an SDK, BPF captures the OBI request
context at entry and parents automatic clients under the active dynamic call:
`OBI server → dynamic outer → dynamic inner → OBI client`. The server's own
tracking state is preserved.

With an active span from the OpenTelemetry Node.js SDK, the wrapper makes a
non-recording span with the dynamic span's context current while the function
runs. SDK-created spans then form `SDK server → dynamic span → SDK client`.
This also works when the SDK registers after OBI injection. The SDK must have
working context propagation and create its client spans. Explicit alternative
parents and root contexts remain under application control. OBI exports the
dynamic span; the SDK exports its own children. Dynamic spans bypass avoided
service suppression, while OBI's duplicate protocol spans retain the existing
suppression behavior. No SDK provider is replaced, and `nodejs.manual_spans` is
not required for dynamic probes.

The injected agent opens a private loopback control socket. It announces its
port, random token, and catalog revision through the existing `uv_fs_access`
side channel. OBI connects in the target network namespace to send concrete
function names and attachment cookies. Attachment errors are returned through
the API; `attached` means the export or method was successfully wrapped. The
inspector is not reopened for subsequent probe changes. A new OBI control session
removes stale registrations left by the previous OBI instance.

Node span entry, completion and async-context switches also use `uv_fs_access`;
there is no native addon dependency or `bpf_probe_write_user` requirement. Dynamic
Node probes do not require attach-cookie support. BPF keeps up to 256 registered
Node probes and 4096 in-flight invocations. An invocation evicted under load may
lose its span or parent context; invocation counters still count entry events.
The catalog scans at most 20,000 objects to five property levels, with at most
100,000 names and 64 MiB of symbol-name data. OBI caches catalogs using the
configured symbol-cache limits and invalidates them when the catalog changes.

Run `make test-nodejs` for agent and SDK regressions. The privileged BPF test
starts an isolated Node HTTP application and verifies parentage, values,
invocation counters, and removal:

```sh
OBI_NODE_AGENT_DIR="$PWD/pkg/internal/nodejs" \
  go test -tags node_live -run '^TestNodeDynamicSpansLive$' -timeout 2m \
  ./pkg/internal/ebpf/generictracer
```
