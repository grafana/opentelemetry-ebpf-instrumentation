/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import java.io.*;
import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;

/**
 * A process-local, capability-protected control channel; the endpoint is advertised through BPF.
 */
public final class DynamicControl {
  private static DynamicControl instance;
  private final DynamicInstrumentation instrumentation;
  private final ServerSocket server;
  private final byte[] token = new byte[16];
  private byte[] owner;

  private DynamicControl(Instrumentation inst) throws Exception {
    instrumentation = new DynamicInstrumentation(inst);
    server = new ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"));
    new SecureRandom().nextBytes(token);
    Thread control = new Thread(this::run, "obi-dynamic-control");
    control.setDaemon(true);
    control.start();
    Thread heartbeat = new Thread(this::advertise, "obi-dynamic-heartbeat");
    heartbeat.setDaemon(true);
    heartbeat.start();
  }

  public static synchronized void start(Instrumentation inst) throws Exception {
    if (instance == null) {
      instance = new DynamicControl(inst);
    }
  }

  private void advertise() {
    NativeMemory packet = new NativeMemory(32);
    packet.setByte(0, OperationType.DYNAMIC_READY.code);
    packet.setInt(4, server.getLocalPort());
    packet.write(8, token, 0, token.length);

    while (!server.isClosed()) {
      packet.setLong(24, ManagementFactory.getClassLoadingMXBean().getTotalLoadedClassCount());
      try {
        Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
        Thread.sleep(1000);
      } catch (InterruptedException stop) {
        Thread.currentThread().interrupt();
        return;
      } catch (Throwable error) {
        return;
      }
    }
  }

  private void run() {
    while (!server.isClosed()) {
      try (Socket socket = server.accept()) {
        socket.setSoTimeout(5000);
        DataInputStream input = new DataInputStream(socket.getInputStream());
        DataOutputStream output = new DataOutputStream(socket.getOutputStream());
        byte[] supplied = new byte[token.length];
        input.readFully(supplied);
        if (!MessageDigest.isEqual(token, supplied)) {
          continue;
        }
        byte[] session = new byte[16];
        input.readFully(session);
        int operation = input.readUnsignedByte();
        try {
          if (operation != 4 && (owner == null || !MessageDigest.isEqual(owner, session))) {
            throw new IllegalStateException("OBI dynamic session has changed");
          }
          List<String> symbols = null;
          switch (operation) {
            case 1:
              symbols = instrumentation.symbols();
              break;
            case 2:
              instrumentation.attach(readString(input), input.readLong());
              break;
            case 3:
              instrumentation.detach(input.readLong());
              break;
            case 4:
              if (owner == null || !MessageDigest.isEqual(owner, session)) {
                instrumentation.reset();
                owner = session;
              }
              break;
            default:
              throw new IllegalArgumentException("Unknown dynamic control operation");
          }
          output.writeByte(0);
          if (symbols != null) {
            output.writeInt(symbols.size());
            for (String symbol : symbols) {
              writeString(output, symbol);
            }
          }
        } catch (Exception error) {
          output.writeByte(1);
          writeString(output, error.toString());
        }
        output.flush();
      } catch (IOException error) {
        if (Agent.debugOn) {
          error.printStackTrace(System.err);
        }
      }
    }
  }

  private static String readString(DataInputStream input) throws IOException {
    int length = input.readInt();
    if (length < 0 || length > 65536) {
      throw new IOException("Invalid string length");
    }
    byte[] bytes = new byte[length];
    input.readFully(bytes);
    return new String(bytes, StandardCharsets.UTF_8);
  }

  private static void writeString(DataOutputStream output, String value) throws IOException {
    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    output.writeInt(bytes.length);
    output.write(bytes);
  }
}
