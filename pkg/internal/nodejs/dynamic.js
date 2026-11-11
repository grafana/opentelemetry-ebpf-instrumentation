// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

(() => {
  const KEY = Symbol.for('otel-ebpf-instrumentation.node.dynamic');
  if (globalThis[KEY]) return;

  const fs = require('fs');
  const net = require('net');
  const crypto = require('crypto');
  const { AsyncLocalStorage, createHook } = require('async_hooks');
  const { types } = require('util');
  const Module = require('module');
  const API = Symbol.for('opentelemetry.js.api.1');
  const SPAN = Symbol.for('OpenTelemetry Context Key SPAN');
  const PREFIX = '/dev/null/obi-dy/';
  const ZERO = '0000000000000000';
  const MAX_SYMBOLS = 100000;
  const MAX_OBJECTS = 20000;
  const MAX_SYMBOL_BYTES = 64 * 1024 * 1024;
  const MAX_DEPTH = 5;
  const MAX_ARGS = 12;
  const MAX_STRING = 127;
  const MAX_PAYLOAD = 1900;
  const MAX_PATCH_REQUEST_BYTES = 262210;
  const scopes = new AsyncLocalStorage();
  const probes = new Map();
  const patches = new Map();
  const wrappers = new WeakMap();
  const token = crypto.randomBytes(16);
  let session;
  let revision = 1n;
  let catalog = new Map();
  let nextInvocation = 0n;
  let emitting = false;
  let lastScope;

  function signal(value) {
    if (emitting) return;
    emitting = true;
    try { fs.existsSync(PREFIX + value); } catch (_) {}
    finally { emitting = false; }
  }

  function current() {
    let scope = scopes.getStore();
    while (scope && (!scope.active || !probes.has(scope.cookie))) scope = scope.previous;
    return scope;
  }

  function refresh() {
    const scope = current();
    if (scope === lastScope) return;
    lastScope = scope;
    signal('c' + (scope ? scope.cookie + scope.id : ZERO + ZERO));
  }

  function stringValue(value) {
    try {
      const text = String(value);
      let end = Math.min(text.length, MAX_STRING);
      while (end && Buffer.byteLength(text.slice(0, end)) > MAX_STRING) end--;
      if (end && /[\uD800-\uDBFF]/.test(text[end - 1])) end--;
      return text.slice(0, end);
    } catch (_) { return undefined; }
  }

  function sdkContext() {
    const api = globalThis[API];
    const manager = api && api.context;
    if (!manager || typeof manager.active !== 'function' || typeof manager.with !== 'function') return;
    const context = manager.active();
    const span = context && context.getValue(SPAN);
    const parent = span && span.spanContext();
    return { manager, context, parent };
  }

  function validParent(parent) {
    return parent && /^[a-f0-9]{32}$/.test(parent.traceId) &&
      parent.traceId !== ZERO + ZERO && /^[a-f0-9]{16}$/.test(parent.spanId) && parent.spanId !== ZERO;
  }

  function nonRecordingSpan(context) {
    return {
      spanContext: () => context,
      isRecording: () => false,
      setAttribute() { return this; }, setAttributes() { return this; },
      addEvent() { return this; }, addLink() { return this; }, addLinks() { return this; },
      setStatus() { return this; }, updateName() { return this; },
      end() {}, recordException() {},
    };
  }

  function invoke(probe, fn, receiver, args) {
    if (!probe.active || emitting) return Reflect.apply(fn, receiver, args);
    let scope;
    let sdk;
    try {
      const previous = current();
      sdk = sdkContext();
      const sdkParent = sdk && validParent(sdk.parent) ? sdk.parent : undefined;
      const sdkRoot = sdk && previous && previous.sdk && !sdkParent;
      if (!sdkParent && !sdkRoot) sdk = undefined;
      const parent = sdkRoot ? undefined : sdkParent || (previous && previous.context);
      const context = {
        traceId: parent ? parent.traceId : crypto.randomBytes(16).toString('hex'),
        spanId: crypto.randomBytes(8).toString('hex'),
        traceFlags: parent ? parent.traceFlags : 1,
        traceState: parent && parent.traceState,
        isRemote: false,
      };
      scope = {
        cookie: probe.cookie, id: (++nextInvocation).toString(16).padStart(16, '0'),
        context, parentId: parent ? parent.spanId : ZERO, previous, active: true, sdk: !!sdk,
        start: process.hrtime.bigint(), attrs: {},
      };
      // Conversion may execute application code. Suppress recursive probes in it.
      emitting = true;
      try {
        for (let i = 0; i < Math.min(args.length, MAX_ARGS); i++) {
          const value = stringValue(args[i]);
          if (value !== undefined) scope.attrs['arg' + i] = value;
        }
      } finally { emitting = false; }
      signal('s' + scope.cookie + scope.id + context.traceId + context.spanId + scope.parentId +
        (context.traceFlags & 255).toString(16).padStart(2, '0') +
        (sdk ? '0' : '1'));
      lastScope = scope;
    } catch (_) { return Reflect.apply(fn, receiver, args); }

    const finish = (value, failed) => {
      if (!scope.active) return;
      scope.active = false;
      try {
        emitting = true;
        let text;
        try { text = stringValue(failed && value ? value.message || value : value); }
        finally { emitting = false; }
        if (text !== undefined) scope.attrs[failed ? 'exception.message' : 'return0'] = text;
        const record = {
          v: 1, name: 'dynamic', tid: scope.context.traceId, sid: scope.context.spanId,
          durNs: String(process.hrtime.bigint() - scope.start),
          status: failed ? 2 : 0, attrs: scope.attrs,
        };
        let payload = JSON.stringify(record);
        // Keep return/exception attributes when the combined argument budget is full.
        for (let i = MAX_ARGS - 1; Buffer.byteLength(payload) > MAX_PAYLOAD && i >= 0; i--) {
          delete record.attrs['arg' + i];
          payload = JSON.stringify(record);
        }
        signal('e' + scope.cookie + scope.id + payload);
      } catch (_) {} finally { refresh(); }
    };

    const call = () => {
      try {
        const result = Reflect.apply(fn, receiver, args);
        if (types.isPromise(result)) {
          // Return the chained promise so rejection semantics remain observable
          // to the caller; an ignored side-chain would mask unhandled rejections.
          return result.then(value => { finish(value, false); return value; }, error => {
            finish(error, true); throw error;
          });
        }
        finish(result, false);
        return result;
      } catch (error) { finish(error, true); throw error; }
    };
    try {
      return scopes.run(scope, () => sdk
        ? sdk.manager.with(sdk.context.setValue(SPAN, nonRecordingSpan(scope.context)), call)
        : call());
    } finally { refresh(); }
  }

  function discover() {
    const found = new Map();
    let visited = 0;
    let symbolBytes = 0;
    for (const mod of Object.values(Module._cache)) {
      if (!mod || !mod.filename || /[/\\]@opentelemetry[/\\]/.test(mod.filename)) continue;
      const seen = new WeakSet();
      function walk(owner, key, value, name, depth, descriptor) {
        if (!value || (typeof value !== 'object' && typeof value !== 'function') || depth > MAX_DEPTH) return;
        const wrapped = wrappers.get(value);
        if (++visited > MAX_OBJECTS || found.size >= MAX_SYMBOLS || (types.isProxy(value) && !wrapped)) return;
        const original = wrapped ? wrapped.original : value;
        if (typeof original === 'function' && descriptor && (descriptor.writable || descriptor.configurable) &&
            !types.isGeneratorFunction(original) && !/^class\s/.test(Function.prototype.toString.call(original))) {
          const bytes = Buffer.byteLength(name);
          if (bytes <= 65536 && symbolBytes + bytes <= MAX_SYMBOL_BYTES) {
            found.set(name, { owner, key, original, descriptor });
            symbolBytes += bytes;
          }
        }
        if (seen.has(value)) return;
        seen.add(value);
        for (const prop of Object.getOwnPropertyNames(value)) {
          if (prop === 'constructor' || prop === 'caller' || prop === 'arguments') continue;
          const desc = Object.getOwnPropertyDescriptor(value, prop);
          if (!desc || !('value' in desc)) continue;
          walk(value, prop, desc.value, name + '.' + prop, depth + 1, desc);
        }
      }
      try {
        walk(mod, 'exports', mod.exports, mod.filename + ':exports', 0,
          Object.getOwnPropertyDescriptor(mod, 'exports'));
      } catch (_) {}
      if (visited > MAX_OBJECTS || found.size >= MAX_SYMBOLS) break;
    }
    if (found.size !== catalog.size || [...found].some(([name, entry]) => {
      const old = catalog.get(name);
      return !old || old.original !== entry.original || old.owner !== entry.owner;
    })) revision++;
    catalog = found;
    return catalog;
  }

  function detach(cookie) {
    const patch = patches.get(cookie);
    if (patch) {
      patch.active = false;
      clearTimeout(patch.timer);
      const descriptor = Object.getOwnPropertyDescriptor(patch.owner, patch.key);
      if (descriptor && descriptor.value === patch.wrapper) {
        Object.defineProperty(patch.owner, patch.key, { ...descriptor, value: patch.original });
      }
      patches.delete(cookie);
      return;
    }
    const probe = probes.get(cookie);
    if (!probe) return;
    probe.active = false;
    const descriptor = Object.getOwnPropertyDescriptor(probe.owner, probe.key);
    if (descriptor && descriptor.value === probe.wrapper) {
      Object.defineProperty(probe.owner, probe.key, { ...descriptor, value: probe.original });
    }
    probes.delete(cookie);
  }

  function attach(name, cookie) {
    const entry = discover().get(name);
    if (!entry) throw new Error('No writable CommonJS function matches ' + name);
    const existing = probes.get(cookie);
    if (existing) {
      if (existing.owner === entry.owner && existing.key === entry.key && existing.active) return;
      throw new Error('patch cookie is already active');
    }
    if (patches.has(cookie)) throw new Error('patch cookie is already active');
    if ([...patches.values()].some(p => p.owner === entry.owner && p.key === entry.key)) {
      throw new Error('function already has a return patch');
    }
    const prior = [...probes.values()].find(p => p.owner === entry.owner && p.key === entry.key);
    const probe = { ...entry, cookie, name, active: true };
    probe.wrapper = new Proxy(entry.original, {
      apply(target, receiver, args) { return invoke(probe, target, receiver, args); },
    });
    Object.defineProperty(entry.owner, entry.key, { ...entry.descriptor, value: probe.wrapper });
    wrappers.set(probe.wrapper, probe);
    probes.set(cookie, probe);
    if (prior) detach(prior.cookie);
  }

  function attachReturn(name, value, expiresAt, cookie) {
    if (typeof value !== 'string') throw new Error('return patch value must be a string');
    const remainingMs = expiresAt - Date.now();
    if (!Number.isSafeInteger(expiresAt) || remainingMs <= 0 || remainingMs > 24 * 60 * 60 * 1000) {
      throw new Error('return patch expiry must be in the next 24 hours');
    }
    const entry = discover().get(name);
    if (!entry) throw new Error('No writable CommonJS function matches ' + name);
    if (patches.has(cookie) || probes.has(cookie)) throw new Error('patch cookie is already active');
    if ([...probes.values()].some(p => p.owner === entry.owner && p.key === entry.key)) throw new Error('function already has a span probe');
    const prior = [...patches.values()].find(p => p.owner === entry.owner && p.key === entry.key);
    const patch = { ...entry, cookie, name, value, active: true,
      deadline: process.hrtime.bigint() + BigInt(remainingMs) * 1000000n };
    patch.wrapper = new Proxy(entry.original, {
      apply(target, receiver, args) {
        if (!patch.active) return Reflect.apply(target, receiver, args);
        if (process.hrtime.bigint() >= patch.deadline) {
          detach(patch.cookie);
          return Reflect.apply(target, receiver, args);
        }
        return patch.value;
      },
    });
    Object.defineProperty(entry.owner, entry.key, { ...entry.descriptor, value: patch.wrapper });
    wrappers.set(patch.wrapper, patch);
    patches.set(cookie, patch);
    if (prior) detach(prior.cookie);
    patch.timer = setTimeout(() => detach(cookie), remainingMs);
    patch.timer.unref();
  }

  function readString(data, offset) {
    if (offset + 4 > data.length) throw new Error('short patch request');
    const size = data.readUInt32BE(offset);
    if (size > 65536 || offset + 4 + size > data.length) throw new Error('invalid patch string');
    return { value: data.subarray(offset + 4, offset + 4 + size).toString(), next: offset + 4 + size };
  }

  function wireString(value) {
    const text = Buffer.from(value);
    const size = Buffer.alloc(4); size.writeUInt32BE(text.length);
    return Buffer.concat([size, text]);
  }

  function command(data) {
    if (!crypto.timingSafeEqual(data.subarray(0, 16), token)) throw new Error('Invalid agent token');
    const requestedSession = data.subarray(16, 32).toString('hex');
    const op = data[32];
    if (op === 4) {
      if (requestedSession !== session) {
        for (const cookie of probes.keys()) detach(cookie);
        for (const cookie of patches.keys()) detach(cookie);
        session = requestedSession;
      }
    } else {
      if (requestedSession !== session) throw new Error('Agent session was replaced');
      if (op === 1) {
        const names = [...discover().keys()].sort();
        const count = Buffer.alloc(4); count.writeUInt32BE(names.length);
        return Buffer.concat([Buffer.from([0]), count, ...names.map(wireString)]);
      }
      if (op === 2) {
        const length = data.readUInt32BE(33);
        attach(data.subarray(37, 37 + length).toString(), data.subarray(37 + length, 45 + length).toString('hex'));
      } else if (op === 3) detach(data.subarray(33, 41).toString('hex'));
      else if (op === 5) {
        const className = readString(data, 33);
        const method = readString(data, className.next);
        const descriptor = readString(data, method.next);
        if (className.value || descriptor.value) throw new Error('Node patches use only a CommonJS export symbol');
        const actionOffset = descriptor.next;
        if (actionOffset + 1 > data.length || data[actionOffset] !== 1) throw new Error('unsupported patch action');
        const value = readString(data, actionOffset + 1);
        if (value.next + 16 !== data.length) throw new Error('invalid patch request length');
        const expiresAt = Number(data.readBigInt64BE(value.next));
        const cookie = data.subarray(value.next + 8, value.next + 16).toString('hex');
        attachReturn(method.value, value.value, expiresAt, cookie);
      }
      else throw new Error('Unknown agent command');
    }
    return Buffer.from([0]);
  }

  const server = net.createServer(socket => {
    socket.unref();
    socket.setTimeout(5000, () => socket.destroy());
    socket.on('error', () => {});
    let data = Buffer.alloc(0);
    let complete = false;
    socket.on('data', chunk => {
      if (complete) return;
      data = Buffer.concat([data, chunk]);
      if (data.length < 33) return;
      const op = data[32];
      if (data.length > (op === 5 ? MAX_PATCH_REQUEST_BYTES : 65581)) { socket.destroy(); return; }
      let length = op === 3 ? 41 : 33;
      if (op === 2) {
        if (data.length < 37) return;
        length = 45 + data.readUInt32BE(33);
        if (length > 65581) { socket.destroy(); return; }
      }
      if (op === 5) {
        // Three length-prefixed identity strings, action byte, return string,
        // absolute expiry and cookie. The overall request stays bounded.
        let offset = 33;
        for (let i = 0; i < 3; i++) {
          if (data.length < offset + 4) return;
          const size = data.readUInt32BE(offset);
          if (size > 65536) { socket.destroy(); return; }
          offset += 4 + size;
          if (data.length < offset) return;
        }
        if (data.length < offset + 1 + 4) return;
        offset++;
        const size = data.readUInt32BE(offset);
        if (size > 65536) { socket.destroy(); return; }
        length = offset + 4 + size + 16;
        if (length > MAX_PATCH_REQUEST_BYTES) { socket.destroy(); return; }
      }
      if (data.length < length) return;
      complete = true;
      try { socket.end(command(data)); }
      catch (error) { socket.end(Buffer.concat([Buffer.from([1]), wireString(String(error.message))])); }
    });
  });
  server.on('error', () => {});
  server.listen(0, '127.0.0.1', () => { server.unref(); announce(); });
  function announce() {
    const address = server.address();
    if (!address) return;
    discover();
    signal('r' + BigInt(address.port).toString(16).padStart(16, '0') + token.toString('hex') +
      revision.toString(16).padStart(16, '0'));
  }
  const hook = createHook({ before: refresh, after: refresh });
  hook.enable();
  const timer = setInterval(announce, 1000);
  timer.unref();
  globalThis[KEY] = { version: 1 };
})();
