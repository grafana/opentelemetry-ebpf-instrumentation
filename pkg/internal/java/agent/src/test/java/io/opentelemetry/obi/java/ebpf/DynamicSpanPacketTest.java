/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class DynamicSpanPacketTest {
  @Test
  void distinguishesAbsentValuesAndPreservesUtf8Boundaries() {
    NativeMemory memory = new NativeMemory(DynamicSpanPacket.PACKET_SIZE, true);
    byte[] ids = new byte[33];
    ids[0] = 1;
    ids[16] = 2;
    ids[24] = 3;
    ids[32] = 1;
    StringBuilder large = new StringBuilder();
    for (int i = 0; i < 100; i++) large.append("界");
    DynamicSpanPacket.write(
        memory,
        OperationType.DYNAMIC_SPAN_START.code,
        11,
        12,
        13,
        ids,
        new String[] {large.toString(), "", "null"});
    assertEquals(7, memory.getShort(4));
    byte[] bytes = new byte[126];
    for (int i = 0; i < bytes.length; i++) bytes[i] = memory.getBuffer().get(112 + i);
    assertEquals(large.substring(0, 42), new String(bytes, StandardCharsets.UTF_8));
    assertEquals(0, memory.getBuffer().get(112 + 126));
    byte[] restored = new byte[33];
    DynamicSpanPacket.readContext(memory, restored);
    assertArrayEquals(ids, restored);
    DynamicSpanPacket.write(
        memory,
        OperationType.DYNAMIC_SPAN_END.code,
        11,
        12,
        13,
        ids,
        new String[] {null, "failure"});
    assertEquals(2, memory.getShort(4));
    assertEquals(0, memory.getBuffer().get(112));
    assertEquals(11, memory.getLong(8));
    assertEquals(12, memory.getLong(16));
  }
}
