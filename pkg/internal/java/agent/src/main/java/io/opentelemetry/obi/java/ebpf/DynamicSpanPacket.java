/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.ebpf;

import java.nio.charset.StandardCharsets;

public final class DynamicSpanPacket {
  public static final int MAX_ARGS = 12;
  public static final int STRING_SIZE = 128;
  // opcode, flags/argc/padding, cookie, invocation, Java thread, context, strings.
  public static final int CONTEXT_OFFSET = 32;
  public static final int STRINGS_OFFSET = 112;
  public static final int PACKET_SIZE = STRINGS_OFFSET + MAX_ARGS * STRING_SIZE;

  private DynamicSpanPacket() {}

  public static void write(
      NativeMemory mem,
      byte opcode,
      long cookie,
      long invocation,
      long thread,
      byte[] ids,
      String[] values) {
    for (int i = 0; i < PACKET_SIZE; i += Long.BYTES) {
      mem.setLong(i, 0);
    }
    mem.setByte(0, opcode);
    mem.setByte(1, ids[32]);
    mem.setByte(2, (byte) Math.min(values.length, MAX_ARGS));
    mem.setLong(8, cookie);
    mem.setLong(16, invocation);
    mem.setLong(24, thread);
    mem.write(CONTEXT_OFFSET, ids, 0, 32);
    for (int i = 0; i < values.length && i < MAX_ARGS; i++) {
      if (values[i] == null) {
        continue;
      }
      mem.setShort(4, (short) (mem.getShort(4) | (1 << i)));
      byte[] text = values[i].getBytes(StandardCharsets.UTF_8);
      int length = Math.min(text.length, STRING_SIZE - 1);
      // Do not split a UTF-8 code point at the capture boundary.
      while (length < text.length && length > 0 && (text[length] & 0xc0) == 0x80) {
        length--;
      }
      mem.write(STRINGS_OFFSET + i * STRING_SIZE, text, 0, length);
    }
  }

  public static void readContext(NativeMemory mem, byte[] ids) {
    for (int i = 0; i < 32; i++) {
      ids[i] = mem.getBuffer().get(CONTEXT_OFFSET + i);
    }
    ids[32] = mem.getBuffer().get(1);
  }
}
