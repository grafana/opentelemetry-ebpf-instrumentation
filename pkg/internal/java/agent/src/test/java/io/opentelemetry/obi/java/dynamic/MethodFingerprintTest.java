/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import net.bytebuddy.jar.asm.Attribute;
import net.bytebuddy.jar.asm.ByteVector;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;

class MethodFingerprintTest {
  private static final String DESCRIPTOR = "(Ljava/lang/String;)Ljava/lang/String;";

  @Test
  void isStableAndIgnoresDebugDataAndOtherMethods() {
    String plain = MethodFingerprint.of(classWith("a", true, false), "lookup", DESCRIPTOR);
    String again = MethodFingerprint.of(classWith("a", true, false), "lookup", DESCRIPTOR);
    String withOtherMethod = MethodFingerprint.of(classWith("a", true, true), "lookup", DESCRIPTOR);

    assertEquals(64, plain.length());
    assertEquals(plain, again);
    assertEquals(plain, withOtherMethod, "a method's fingerprint must not depend on its siblings");
  }

  @Test
  void changesWithTheMethodBody() {
    assertNotEquals(
        MethodFingerprint.of(classWith("a", true, false), "lookup", DESCRIPTOR),
        MethodFingerprint.of(classWith("b", true, false), "lookup", DESCRIPTOR));
    assertNotEquals(
        MethodFingerprint.of(classWith("a", true, false), "lookup", DESCRIPTOR),
        MethodFingerprint.of(classWith("a", false, false), "lookup", DESCRIPTOR));
  }

  @Test
  void keepsUnpairedSurrogatesDistinct() {
    assertNotEquals(
        MethodFingerprint.of(classWith("\uD800", true, false), "lookup", DESCRIPTOR),
        MethodFingerprint.of(classWith("\uD801", true, false), "lookup", DESCRIPTOR));
  }

  @Test
  void failsClosedOnAnUnknownAttributeOrAMissingMethod() {
    assertThrows(
        IllegalArgumentException.class,
        () -> MethodFingerprint.of(classWithUnknownAttribute(), "lookup", DESCRIPTOR));
    assertThrows(
        IllegalArgumentException.class,
        () -> MethodFingerprint.of(classWith("a", true, false), "lookup", "(I)Ljava/lang/String;"));
  }

  private static byte[] classWith(String constant, boolean branch, boolean extraMethod) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "fp/Sample", null, "java/lang/Object", null);
    MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "lookup", DESCRIPTOR, null, null);
    method.visitCode();
    Label end = new Label();
    if (branch) {
      method.visitVarInsn(Opcodes.ALOAD, 1);
      method.visitJumpInsn(Opcodes.IFNULL, end);
    }
    method.visitLdcInsn(constant);
    method.visitInsn(Opcodes.ARETURN);
    method.visitLabel(end);
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitInsn(Opcodes.ARETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    if (extraMethod) {
      MethodVisitor other = writer.visitMethod(Opcodes.ACC_PUBLIC, "other", "()V", null, null);
      other.visitCode();
      other.visitLineNumber(7, new Label());
      other.visitInsn(Opcodes.RETURN);
      other.visitMaxs(0, 0);
      other.visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] classWithUnknownAttribute() {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "fp/Sample", null, "java/lang/Object", null);
    writer.visitAttribute(
        new Attribute("FleetOpsUnknown") {
          @Override
          protected ByteVector write(
              ClassWriter cw, byte[] code, int codeLength, int maxStack, int maxLocals) {
            return new ByteVector().putByte(1);
          }
        });
    MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "lookup", DESCRIPTOR, null, null);
    method.visitCode();
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitInsn(Opcodes.ARETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }
}
