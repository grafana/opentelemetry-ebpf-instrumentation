/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DynamicInstrumentationTest {
  @TempDir File directory;

  @Test
  void advicePreservesApplicationBehaviorAndSdkContext() throws Exception {
    runFixture(null);
  }

  @Test
  void interoperatesWithOpenTelemetryJavaAgent() throws Exception {
    String agent = System.getenv("OBI_TEST_OTEL_AGENT_JAR");
    Assumptions.assumeTrue(agent != null, "set OBI_TEST_OTEL_AGENT_JAR for agent coexistence test");
    runFixture(agent);
  }

  private void runFixture(String otelAgent) throws Exception {
    File output = new File(directory, "output");
    List<String> command = new ArrayList<>();
    command.add(System.getProperty("java.home") + "/bin/java");
    if (otelAgent != null) {
      command.add("-javaagent:" + otelAgent);
      command.add("-Dotel.traces.exporter=none");
      command.add("-Dotel.metrics.exporter=none");
      command.add("-Dotel.logs.exporter=none");
    }
    command.add(
        "-javaagent:" + System.getProperty("obi.agent.jar") + "=dynamicInstrumentation=true");
    command.add("-cp");
    command.add(System.getProperty("obi.test.classpath"));
    command.add(
        otelAgent == null ? "testutil.DynamicProbeTarget" : "testutil.AgentDynamicProbeTarget");
    Process process =
        new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(output).start();
    try {
      assertTrue(process.waitFor(60, TimeUnit.SECONDS), "fixture timed out");
      String log = new String(Files.readAllBytes(output.toPath()), StandardCharsets.UTF_8);
      assertEquals(0, process.exitValue(), log);
      assertTrue(log.contains("DYNAMIC_OK"), log);
    } finally {
      process.destroyForcibly();
    }
  }
}
