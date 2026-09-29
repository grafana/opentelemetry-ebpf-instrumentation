// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

exports.inner = function inner(value) { return value + 1; };
exports.outer = function outer(value) { return exports.inner(value) * 2; };
exports.asyncCall = async function asyncCall(value, callback) {
  await new Promise(resolve => setTimeout(resolve, value));
  return callback(value);
};
exports.fail = function fail(error) { throw error; };
exports.identity = function identity(value) { return value; };
exports.Worker = class Worker {
  constructor(value) { this.value = value; }
  run(value) { return this.value + value; }
};
