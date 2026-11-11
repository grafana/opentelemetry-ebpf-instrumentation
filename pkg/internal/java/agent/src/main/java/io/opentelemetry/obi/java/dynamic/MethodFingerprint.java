/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import java.lang.instrument.ClassFileTransformer;
import java.security.MessageDigest;
import java.security.ProtectionDomain;
import java.util.IdentityHashMap;
import java.util.Map;
import net.bytebuddy.jar.asm.Attribute;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ConstantDynamic;
import net.bytebuddy.jar.asm.Handle;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;

/**
 * Canonical-v1 method fingerprint: a SHA-256 over the method's resolved instructions, independent
 * of constant-pool layout, debug data and stack frames. The encoding is the one the E15 identity
 * fixture (T3) validated, so the two produce the same value for the same method. Anything the
 * serializer does not understand (unknown attributes, unsupported constants) fails closed.
 */
final class MethodFingerprint {
  static final String VERSION = "canonical-v1";

  private MethodFingerprint() {}

  /** Fingerprint of one method, from the class file bytes. */
  static String of(byte[] classBytes, final String method, final String descriptor) {
    final StringBuilder code = new StringBuilder();
    new ClassReader(classBytes)
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public void visitAttribute(Attribute attribute) {
                throw new IllegalArgumentException(
                    "unsupported class attribute: " + attribute.type);
              }

              @Override
              public MethodVisitor visitMethod(
                  int access, String name, String desc, String signature, String[] exceptions) {
                if (!method.equals(name) || !descriptor.equals(desc)) {
                  return null;
                }
                record(code, "method", Integer.toString(access), desc);
                return new Canonical(code);
              }
            },
            ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    if (code.length() == 0) {
      throw new IllegalArgumentException("exact method absent");
    }
    return sha256(code.toString());
  }

  /**
   * Captures the fingerprint of one class while it is being retransformed. Registered before any
   * other transformer of this agent, so it sees the bytes before this agent changed them.
   */
  static final class Capture implements ClassFileTransformer {
    private volatile Class<?> target;
    private volatile String method;
    private volatile String descriptor;
    private volatile String fingerprint;
    private volatile String failure;

    void arm(Class<?> type, String methodName, String methodDescriptor) {
      fingerprint = null;
      failure = null;
      method = methodName;
      descriptor = methodDescriptor;
      target = type;
    }

    String fingerprint() {
      return fingerprint;
    }

    String failure() {
      return failure;
    }

    void disarm() {
      target = null;
    }

    @Override
    public byte[] transform(
        ClassLoader loader,
        String className,
        Class<?> redefined,
        ProtectionDomain domain,
        byte[] bytes) {
      if (redefined == null || redefined != target) {
        return null;
      }
      try {
        fingerprint = of(bytes, method, descriptor);
      } catch (Throwable error) {
        failure = error.getClass().getSimpleName() + ": " + error.getMessage();
      }
      return null;
    }
  }

  private static final class Canonical extends MethodVisitor {
    private final StringBuilder out;
    private final Map<Label, Integer> labels = new IdentityHashMap<>();

    Canonical(StringBuilder out) {
      super(Opcodes.ASM9);
      this.out = out;
    }

    private int label(Label label) {
      Integer id = labels.get(label);
      if (id == null) {
        id = labels.size();
        labels.put(label, id);
      }
      return id;
    }

    @Override
    public void visitAttribute(Attribute attribute) {
      throw new IllegalArgumentException("unsupported method/code attribute: " + attribute.type);
    }

    @Override
    public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
      record(
          out,
          "try",
          Integer.toString(label(start)),
          Integer.toString(label(end)),
          Integer.toString(label(handler)),
          type);
    }

    @Override
    public void visitLabel(Label label) {
      record(out, "label", Integer.toString(label(label)));
    }

    @Override
    public void visitInsn(int opcode) {
      record(out, "insn", Integer.toString(opcode));
    }

    @Override
    public void visitIntInsn(int opcode, int operand) {
      record(out, "int", Integer.toString(opcode), Integer.toString(operand));
    }

    @Override
    public void visitVarInsn(int opcode, int var) {
      record(out, "var", Integer.toString(opcode), Integer.toString(var));
    }

    @Override
    public void visitTypeInsn(int opcode, String type) {
      record(out, "typeInsn", Integer.toString(opcode), type);
    }

    @Override
    public void visitFieldInsn(int opcode, String owner, String name, String desc) {
      record(out, "field", Integer.toString(opcode), owner, name, desc);
    }

    @Override
    public void visitMethodInsn(
        int opcode, String owner, String name, String desc, boolean isInterface) {
      record(
          out,
          "methodInsn",
          Integer.toString(opcode),
          owner,
          name,
          desc,
          Boolean.toString(isInterface));
    }

    @Override
    public void visitInvokeDynamicInsn(
        String name, String desc, Handle bootstrap, Object... arguments) {
      String[] values = new String[3 + arguments.length];
      values[0] = name;
      values[1] = desc;
      values[2] = constant(bootstrap);
      for (int i = 0; i < arguments.length; i++) {
        values[i + 3] = constant(arguments[i]);
      }
      record(out, "invokeDynamic", values);
    }

    @Override
    public void visitJumpInsn(int opcode, Label target) {
      record(out, "jump", Integer.toString(opcode), Integer.toString(label(target)));
    }

    @Override
    public void visitLdcInsn(Object value) {
      record(out, "ldc", constant(value));
    }

    @Override
    public void visitIincInsn(int var, int increment) {
      record(out, "iinc", Integer.toString(var), Integer.toString(increment));
    }

    @Override
    public void visitTableSwitchInsn(int min, int max, Label dflt, Label... targets) {
      String[] values = new String[3 + targets.length];
      values[0] = Integer.toString(min);
      values[1] = Integer.toString(max);
      values[2] = Integer.toString(label(dflt));
      for (int i = 0; i < targets.length; i++) {
        values[i + 3] = Integer.toString(label(targets[i]));
      }
      record(out, "tableSwitch", values);
    }

    @Override
    public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] targets) {
      String[] values = new String[1 + keys.length * 2];
      values[0] = Integer.toString(label(dflt));
      for (int i = 0; i < keys.length; i++) {
        values[1 + i * 2] = Integer.toString(keys[i]);
        values[2 + i * 2] = Integer.toString(label(targets[i]));
      }
      record(out, "lookupSwitch", values);
    }

    @Override
    public void visitMultiANewArrayInsn(String desc, int dims) {
      record(out, "multiANewArray", desc, Integer.toString(dims));
    }

    private String constant(Object value) {
      if (value instanceof Type) {
        return tuple("type", ((Type) value).getDescriptor());
      }
      if (value instanceof Handle) {
        Handle handle = (Handle) value;
        return tuple(
            "handle",
            Integer.toString(handle.getTag()),
            handle.getOwner(),
            handle.getName(),
            handle.getDesc(),
            Boolean.toString(handle.isInterface()));
      }
      if (value instanceof ConstantDynamic) {
        ConstantDynamic dynamic = (ConstantDynamic) value;
        String[] values = new String[3 + dynamic.getBootstrapMethodArgumentCount()];
        values[0] = dynamic.getName();
        values[1] = dynamic.getDescriptor();
        values[2] = constant(dynamic.getBootstrapMethod());
        for (int i = 0; i < dynamic.getBootstrapMethodArgumentCount(); i++) {
          values[i + 3] = constant(dynamic.getBootstrapMethodArgument(i));
        }
        return tuple("constantDynamic", values);
      }
      if (value instanceof Float) {
        return tuple("floatBits", Integer.toHexString(Float.floatToRawIntBits((Float) value)));
      }
      if (value instanceof Double) {
        return tuple("doubleBits", Long.toHexString(Double.doubleToRawLongBits((Double) value)));
      }
      if (value instanceof String) {
        return tuple("string", (String) value);
      }
      if (value instanceof Integer
          || value instanceof Long
          || value instanceof Byte
          || value instanceof Short
          || value instanceof Character
          || value instanceof Boolean) {
        return tuple(value.getClass().getName(), String.valueOf(value));
      }
      throw new IllegalArgumentException(
          "unsupported constant: " + (value == null ? "null" : value.getClass().getName()));
    }
  }

  private static void record(StringBuilder out, String type, String... values) {
    out.append(tuple(type, values));
  }

  private static String tuple(String type, String... values) {
    StringBuilder out = new StringBuilder();
    appendField(out, type);
    appendField(out, Integer.toString(values.length));
    for (String value : values) {
      appendField(out, value);
    }
    return out.toString();
  }

  private static void appendField(StringBuilder out, String value) {
    if (value == null) {
      out.append('N');
      return;
    }
    out.append('S').append(value.length()).append(':').append(value);
  }

  /** Hashes UTF-16 code units, so unpaired surrogates stay distinct. */
  private static String sha256(String text) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (int i = 0; i < text.length(); i++) {
        char codeUnit = text.charAt(i);
        digest.update((byte) (codeUnit >>> 8));
        digest.update((byte) codeUnit);
      }
      StringBuilder out = new StringBuilder();
      for (byte b : digest.digest()) {
        out.append(String.format("%02x", b & 255));
      }
      return out.toString();
    } catch (java.security.NoSuchAlgorithmException error) {
      throw new IllegalStateException(error);
    }
  }
}
