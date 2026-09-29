// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

for (const scenario of ['obi', 'sdk', 'late-sdk', 'sdk-idle']) {
  test('dynamic calls, removal and asynchronous parenting: ' + scenario, () => {
    const result = JSON.parse(execFileSync(process.execPath,
      [path.join(__dirname, 'scenario_dynamic.cjs'), scenario], { encoding: 'utf8', timeout: 15000 }));
    assert.equal(result.ok, true);
    assert.ok(result.calls >= 8);
  });
}
