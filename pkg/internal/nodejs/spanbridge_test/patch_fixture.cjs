// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

let calls = 0;

exports.choke = function choke(value) {
  calls++;
  return `canary:${value}`;
};

exports.otherChoke = value => `other:${value}`;

exports.dynamicCaller = value => exports.choke(value);
const cached = exports.choke;
exports.destructuredCaller = value => cached(value);
exports.closureCaller = (() => {
  const closedOver = exports.choke;
  return value => closedOver(value);
})();
exports.callCount = () => calls;
