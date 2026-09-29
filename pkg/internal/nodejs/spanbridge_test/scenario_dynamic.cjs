// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const net = require('net');
const path = require('path');
const fixture = require('./dynamic_fixture.cjs');
const { trace, context, ROOT_CONTEXT } = require('@opentelemetry/api');
const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
const sdkSpans = [];
const provider = new NodeTracerProvider({ spanProcessors: [{
  onStart() {}, onEnd(span) { sdkSpans.push(span); },
  shutdown() { return Promise.resolve(); }, forceFlush() { return Promise.resolve(); },
}] });
const scenario = process.argv[2];
if (scenario === 'sdk' || scenario === 'sdk-idle') provider.register();
const signals = [];
let endpoint;
const originalExists = fs.existsSync;
fs.existsSync = function (value, ...args) {
  if (typeof value === 'string' && value.startsWith('/dev/null/obi-dy/')) {
    const data = value.slice('/dev/null/obi-dy/'.length);
    if (data[0] === 'r') endpoint = { port: Number.parseInt(data.slice(1, 17), 16), token: data.slice(17, 49) };
    else signals.push(data);
    return false;
  }
  return originalExists.call(this, value, ...args);
};
eval(fs.readFileSync(path.join(__dirname, '..', 'dynamic.js'), 'utf8'));
const session = Buffer.alloc(16, 7);
function command(op, name, cookie = 0n, token) {
  const parts = [Buffer.from(token || endpoint.token, 'hex'), session, Buffer.from([op])];
  if (op === 2) {
    const text = Buffer.from(name); const size = Buffer.alloc(4); size.writeUInt32BE(text.length);
    parts.push(size, text);
  }
  if (op === 2 || op === 3) { const id = Buffer.alloc(8); id.writeBigUInt64BE(cookie); parts.push(id); }
  return new Promise((resolve, reject) => {
    const socket = net.connect(endpoint.port, '127.0.0.1', () => socket.write(Buffer.concat(parts)));
    const chunks = [];
    socket.on('data', chunk => chunks.push(chunk)); socket.on('error', reject);
    socket.on('end', () => {
      const response = Buffer.concat(chunks);
      if (response[0]) reject(new Error(response.subarray(5).toString()));
      else resolve(response);
    });
  });
}
const symbol = name => path.join(__dirname, 'dynamic_fixture.cjs') + ':exports.' + name;
const events = () => signals.filter(value => value[0] === 'e').map(value => ({
  cookie: value.slice(1, 17), invocation: value.slice(17, 33), ...JSON.parse(value.slice(33)),
}));
const starts = () => signals.filter(value => value[0] === 's').map(value => ({
  cookie: value.slice(1, 17), invocation: value.slice(17, 33), tid: value.slice(33, 65),
  sid: value.slice(65, 81), psid: value.slice(81, 97), flags: value.slice(97, 99), adopt: value[99],
}));
async function run() {
  while (!endpoint) await new Promise(resolve => setTimeout(resolve, 5));
  await assert.rejects(command(4, '', 0n, '00'.repeat(16)), /token/);
  await command(4);
  const list = await command(1);
  assert.ok(list.includes(Buffer.from(symbol('Worker.prototype.run'))));
  await assert.rejects(command(2, symbol('missing'), 9n), /No writable/);
  const original = fixture.outer;
  await command(2, symbol('outer'), 1n);
  await command(2, symbol('inner'), 2n);
  assert.equal(fixture.outer(20), 42);
  const nested = starts().slice(-2);
  assert.equal(nested[1].psid, nested[0].sid);
  assert.equal(events().find(span => span.cookie.endsWith('1')).attrs.return0, '42');
  await command(2, symbol('Worker.prototype.run'), 3n);
  assert.equal(new fixture.Worker(4).run(5), 9);
  await command(2, symbol('fail'), 4n);
  const error = new Error('expected');
  assert.throws(() => fixture.fail(error), value => value === error);
  assert.equal(events().at(-1).attrs['exception.message'], 'expected');
  await command(2, symbol('identity'), 5n);
  const hostile = { toString() { throw error; } };
  assert.equal(fixture.identity(hostile), hostile);
  assert.equal(events().at(-1).attrs.arg0, undefined);
  await command(2, symbol('asyncCall'), 6n);
  if (scenario === 'late-sdk') provider.register();
  if (scenario === 'sdk' || scenario === 'late-sdk') {
    const tracer = trace.getTracer('test');
    await Promise.all([12, 3].map(delay => tracer.startActiveSpan('server' + delay, async server => {
      try {
        return await fixture.asyncCall(delay, value => {
          tracer.startActiveSpan('client' + value, child => child.end());
          context.with(ROOT_CONTEXT, () => fixture.inner(value));
          assert.equal(starts().at(-1).psid, '0000000000000000');
          assert.equal(starts().at(-1).adopt, '0');
          return value;
        });
      } finally { server.end(); }
    })));
    for (const delay of [12, 3]) {
      const server = sdkSpans.find(span => span.name === 'server' + delay);
      const client = sdkSpans.find(span => span.name === 'client' + delay);
      const custom = starts().find(span => span.psid === server.spanContext().spanId);
      assert.ok(custom);
      assert.equal(custom.tid, server.spanContext().traceId);
      assert.equal(client.parentSpanContext.spanId, custom.sid);
      assert.equal(client.spanContext().traceId, custom.tid);
      assert.equal(custom.adopt, '0');
    }
    assert.equal(trace.getActiveSpan(), undefined);
    assert.equal(sdkSpans.length, 4, 'only the application exports SDK spans');
  } else {
    await Promise.all([12, 3].map(delay => fixture.asyncCall(delay, value => fixture.inner(value))));
    const roots = starts().filter(span => span.cookie.endsWith('6'));
    for (const child of starts().filter(span => span.cookie.endsWith('2')).slice(-2)) {
      assert.ok(roots.some(root => root.sid === child.psid && root.tid === child.tid));
    }
  }
  if (scenario === 'sdk-idle') {
    assert.ok(starts().every(span => span.adopt === '1'), 'idle SDK must leave OBI context authoritative');
  }
  await command(3, '', 1n);
  assert.equal(fixture.outer, original);
  const before = starts().filter(span => span.cookie.endsWith('1')).length;
  fixture.outer(1);
  assert.equal(starts().filter(span => span.cookie.endsWith('1')).length, before);
  await command(2, symbol('inner'), 7n);
  await command(2, symbol('inner'), 7n);
  await command(3, '', 2n);
  fixture.inner(1);
  assert.ok(starts().at(-1).cookie.endsWith('7'), 'old deletion must preserve replacement');
  for (const cookie of [3n, 4n, 5n, 6n, 7n]) await command(3, '', cookie);
  fs.existsSync = originalExists;
  console.log(JSON.stringify({ ok: true, scenario, calls: events().length }));
}
run().catch(error => { console.error(error); process.exitCode = 1; });
