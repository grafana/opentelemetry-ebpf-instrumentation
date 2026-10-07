/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import io.opentelemetry.obi.java.Agent;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReferenceArray;

public class ThreadInfo {
  private static final ThreadLocal<NativeMemory> DYNAMIC_TASK_PACKET = new ThreadLocal<>();
  private static final Map<Future<?>, Object> SCHEDULED_TASKS =
      Collections.synchronizedMap(new WeakHashMap<>());
  private static volatile boolean dynamicTaskContextEnabled;

  public static void enableDynamicTaskContext() {
    dynamicTaskContextEnabled = true;
  }

  public static void captureDynamicTaskContext(Object task) {
    emitDynamicTaskOp(OperationType.DYNAMIC_TASK_CAPTURE, task);
  }

  // Wrap scheduled Runnable tasks before the scheduler can dispatch them. A
  // ScheduledThreadPoolExecutor may start its worker before schedule() returns,
  // so capturing the returned ScheduledFuture is inherently racy.
  public static Runnable wrapScheduledRunnable(Runnable task) {
    if (!dynamicTaskContextEnabled || task == null || onVirtualThread() || loomTask(task)) {
      return task;
    }
    DynamicTaskRunnable wrapped = new DynamicTaskRunnable(task);
    captureDynamicTaskContext(wrapped);
    return wrapped;
  }

  public static boolean isDynamicTaskRunnable(Object task) {
    return task instanceof DynamicTaskRunnable;
  }

  public static final class DynamicTaskRunnable implements Runnable {
    private final Runnable delegate;

    private DynamicTaskRunnable(Runnable delegate) {
      this.delegate = Objects.requireNonNull(delegate);
    }

    @Override
    public void run() {
      enterDynamicTaskContext(this);
      try {
        delegate.run();
      } finally {
        exitDynamicTaskContext(this);
      }
    }
  }

  public static void enterDynamicTaskContext(Object task) {
    emitDynamicTaskOp(OperationType.DYNAMIC_TASK_ENTER, task);
  }

  public static void exitDynamicTaskContext(Object task) {
    emitDynamicTaskOp(OperationType.DYNAMIC_TASK_EXIT, task);
  }

  public static void cancelDynamicTaskContext(Object task) {
    emitDynamicTaskOp(OperationType.DYNAMIC_TASK_CANCEL, task);
  }

  public static void associateScheduledTask(Future<?> future, Object task) {
    if (future == null || task == null) {
      return;
    }
    Object taskToCancel = null;
    synchronized (SCHEDULED_TASKS) {
      if (future.isDone()) {
        taskToCancel = task;
      } else {
        SCHEDULED_TASKS.put(future, task);
        // The scheduled task can win the race against schedule() returning.
        if (future.isDone()) {
          taskToCancel = SCHEDULED_TASKS.remove(future);
        }
      }
    }
    if (taskToCancel != null) {
      cancelDynamicTaskContext(future);
      cancelDynamicTaskContext(taskToCancel);
    }
  }

  public static void cancelScheduledTaskContext(Future<?> future) {
    Object task;
    synchronized (SCHEDULED_TASKS) {
      task = SCHEDULED_TASKS.remove(future);
    }
    cancelDynamicTaskContext(future);
    cancelDynamicTaskContext(task);
  }

  public static void completeScheduledTaskContext(Future<?> future) {
    Object task;
    synchronized (SCHEDULED_TASKS) {
      task = SCHEDULED_TASKS.remove(future);
    }
    cancelDynamicTaskContext(future);
    cancelDynamicTaskContext(task);
  }

  private static void emitDynamicTaskOp(OperationType op, Object task) {
    if (!dynamicTaskContextEnabled || task == null || onVirtualThread() || loomTask(task)) {
      return;
    }
    NativeMemory packet = DYNAMIC_TASK_PACKET.get();
    if (packet == null) {
      packet = new NativeMemory(8);
      DYNAMIC_TASK_PACKET.set(packet);
    }
    packet.setByte(0, op.code);
    packet.setInt(1, System.identityHashCode(task));
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
  }

  public static int writeThreadContext(NativeMemory mem, int off, long parentId) {
    mem.setLong(off, parentId);
    off += Long.BYTES;
    return off;
  }

  public static void sendParentThreadContext(long parentId) {
    NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize);
    IOCTLPacket.writePacket(p, 0, OperationType.THREAD, parentId);
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, p.getAddress());
  }

  // Emit variant for the thread-pool task advices. On a virtual thread the
  // tracked parent tid is whatever platform thread submitted the task (e.g.
  // the Tomcat Poller), which never owns the server trace: emitting it would
  // overwrite the correct carrier->origin edge from the mount hook.
  public static void sendTaskParentThreadContext(long parentId) {
    if (onVirtualThread()) {
      return;
    }
    sendParentThreadContext(parentId);
  }

  // Cheap virtual-thread check that compiles on Java 8 (no Thread.isVirtual()
  // in the agent's compile target): java.lang.VirtualThread is final, so the
  // class-name comparison is exact.
  public static boolean onVirtualThread() {
    return "java.lang.VirtualThread".equals(Thread.currentThread().getClass().getName());
  }

  // True for Loom scheduler-internal task objects: the per-VT runContinuation
  // lambda (hidden class named "java.lang.VirtualThread$$Lambda/0x...") and
  // the VirtualThread$VThreadContinuation wrappers. They pass through the
  // instrumented Executor surface on every unpark, submitted from platform
  // threads, so a current-thread check cannot filter them.
  public static boolean loomTask(Object task) {
    return task != null && task.getClass().getName().startsWith("java.lang.VirtualThread");
  }

  public static boolean loomTaskOrVirtualThread(Object task) {
    return onVirtualThread() || loomTask(task);
  }

  // Preallocated buffers for the VT mount/unmount emits. Everything on the
  // mount/unmount path must stay lock-free and must never enter
  // ByteBuffer.allocateDirect (Bits.reserveMemory can run System.gc() and
  // sleep), or carriers can stall inside VirtualThread.mount(). Slots are
  // claimed and released with lock-free CAS. The pool holds one buffer per
  // carrier thread (sized from availableProcessors, rounded up to a power of
  // two), so at most one in-flight emit per carrier never exhausts it. Armed
  // off the mount path by initVtEmitPool, called at agent install AFTER the
  // native library is registered for this classloader copy (the NativeMemory
  // constructor needs the JNI binding, so the allocations cannot live in the
  // static initializer). Until armed, or in the by-construction-unreachable
  // case that every slot is claimed, the emit is dropped rather than
  // allocating: a dropped mount falls back to carrier-tid keying, and a
  // dropped unmount is reaped by the sys_exit backstop and LRU eviction.
  private static final int VT_POOL_SIZE = vtPoolSize();
  private static final AtomicReferenceArray<NativeMemory> vtEmitPool =
      new AtomicReferenceArray<>(VT_POOL_SIZE);
  private static volatile boolean vtEmitPoolReady;

  private static int vtPoolSize() {
    int carriers = Math.max(Runtime.getRuntime().availableProcessors() * 2, 64);
    int size = Integer.highestOneBit(carriers);
    return size < carriers ? size << 1 : size;
  }

  // Called once at agent install, on the bootstrap-injected classloader copy
  // (the one the VirtualThread advices resolve).
  public static void initVtEmitPool() {
    for (int i = 0; i < VT_POOL_SIZE; i++) {
      vtEmitPool.set(i, new NativeMemory(IOCTLPacket.packetPrefixSize));
    }
    vtEmitPoolReady = true;
  }

  private static void emitVtOp(OperationType op, long value) {
    if (!vtEmitPoolReady) {
      return;
    }
    final int start = (int) Thread.currentThread().getId() & (VT_POOL_SIZE - 1);
    for (int i = 0; i < VT_POOL_SIZE; i++) {
      final int slot = (start + i) & (VT_POOL_SIZE - 1);
      final NativeMemory mem = vtEmitPool.getAndSet(slot, null);
      if (mem != null) {
        try {
          IOCTLPacket.writePacket(mem, 0, op, value);
          Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, mem.getAddress());
        } finally {
          vtEmitPool.set(slot, mem);
        }
        return;
      }
    }
  }

  // Called at VirtualThread.mount() EXIT, when Thread.currentThread() is
  // already the virtual thread. Thread.getId() (same value as threadId())
  // keeps the agent compatible with its Java 8 compile target.
  public static void onVirtualThreadMount() {
    emitVtOp(OperationType.VT_MOUNT, Thread.currentThread().getId());
  }

  // Called at VirtualThread.unmount() EXIT. Deletes java_vt_threads[carrier]
  // so a carrier with no mounted VT is never translated. No compare-and-delete
  // is needed: mount and unmount for a given carrier always execute on that
  // carrier OS thread, so its map entry is written and deleted in program
  // order.
  public static void onVirtualThreadUnmount() {
    emitVtOp(OperationType.VT_UNMOUNT, 0L);
  }
}
