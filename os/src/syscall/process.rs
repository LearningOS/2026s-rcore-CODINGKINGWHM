//! Process management syscalls

use crate::{
    task::{exit_current_and_run_next, suspend_current_and_run_next, current_process, pid2process, add_task_to_ready_queue, TaskStatus},
    timer::get_time_us,
    signal::SignalFlags,
    trap::context::TrapContext,
    mm::check_user_ptr_valid,
};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

const PTRACE_ATTACH: usize = 16;
const PTRACE_DETACH: usize = 17;
const PTRACE_GETREGS: usize = 12;
const PTRACE_SETREGS: usize = 13;
const PTRACE_CONT: usize = 7;

const ESRCH: isize = -3;
const EPERM: isize = -1;
const EFAULT: isize = -14;

pub fn sys_exit(exit_code: i32) -> ! {
    trace!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    unsafe {
        *ts = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
    }
    0
}

pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace request={}, pid={}, data={}", trace_request, id, data);
    let tracer_process = current_process();

    match trace_request {
        PTRACE_ATTACH => {
            let Some(tracee_process) = pid2process(id) else {
                return ESRCH;
            };
            let mut tracee_inner = tracee_process.inner_exclusive_access();
            if tracee_inner.tracer.is_some() {
                return EPERM;
            }
            tracee_inner.tracer = Some(Arc::downgrade(&tracer_process));
            tracee_inner.trace_stopped = false;
            tracee_inner.signals.insert(SignalFlags::SIGSTOP);
            let mut tracer_inner = tracer_process.inner_exclusive_access();
            tracer_inner.tracees.push(tracee_process.clone());
            0
        }
        PTRACE_GETREGS => {
            let Some(tracee_process) = pid2process(id) else {
                return ESRCH;
            };
            let tracee_inner = tracee_process.inner_exclusive_access();
            let is_legal_tracer = tracee_inner.tracer.as_ref()
                .and_then(|weak_tracer| weak_tracer.upgrade())
                .map_or(false, |t| Arc::ptr_eq(&t, &tracer_process));
            if !is_legal_tracer {
                return EPERM;
            }
            if !tracee_inner.trace_stopped {
                return EPERM;
            }
            let Some(Some(main_task)) = tracee_inner.tasks.get(0) else {
                return ESRCH;
            };
            let task_inner = main_task.inner_exclusive_access();
            let trap_cx = task_inner.get_trap_cx();
            let user_buf = data as *mut TrapContext;
            if !check_user_ptr_valid(user_buf) {
                return EFAULT;
            }
            unsafe { *user_buf = trap_cx.clone(); }
            0
        }
        PTRACE_SETREGS => {
            let Some(tracee_process) = pid2process(id) else {
                return ESRCH;
            };
            let tracee_inner = tracee_process.inner_exclusive_access();
            let is_legal_tracer = tracee_inner.tracer.as_ref()
                .and_then(|weak| weak.upgrade())
                .map_or(false, |t| Arc::ptr_eq(&t, &tracer_process));
            if !is_legal_tracer || !tracee_inner.trace_stopped {
                return EPERM;
            }
            let Some(Some(main_task)) = tracee_inner.tasks.get(0) else {
                return ESRCH;
            };
            let mut task_inner = main_task.inner_exclusive_access();
            let trap_cx_mut = task_inner.get_trap_cx_mut();
            let user_buf = data as *const TrapContext;
            if !check_user_ptr_valid(user_buf) {
                return EFAULT;
            }
            unsafe { *trap_cx_mut = user_buf.read(); }
            0
        }
        PTRACE_CONT => {
            let Some(tracee_process) = pid2process(id) else {
                return ESRCH;
            };
            let mut tracee_inner = tracee_process.inner_exclusive_access();
            let is_legal_tracer = tracee_inner.tracer.as_ref()
                .and_then(|weak| weak.upgrade())
                .map_or(false, |t| Arc::ptr_eq(&t, &tracer_process));
            if !is_legal_tracer || !tracee_inner.trace_stopped {
                return EPERM;
            }
            tracee_inner.trace_stopped = false;
            let signal = SignalFlags::from_bits(data as u32).unwrap_or(SignalFlags::empty());
            if !signal.is_empty() {
                tracee_inner.signals.insert(signal);
            }
            if let Some(Some(main_task)) = tracee_inner.tasks.get(0) {
                let mut task_inner = main_task.inner_exclusive_access();
                if task_inner.task_status == TaskStatus::Blocked {
                    task_inner.task_status = TaskStatus::Ready;
                    add_task_to_ready_queue(main_task.clone());
                }
            }
            0
        }
        PTRACE_DETACH => {
            let Some(tracee_process) = pid2process(id) else {
                return ESRCH;
            };
            let mut tracee_inner = tracee_process.inner_exclusive_access();
            let is_legal_tracer = tracee_inner.tracer.as_ref()
                .and_then(|weak| weak.upgrade())
                .map_or(false, |t| Arc::ptr_eq(&t, &tracer_process));
            if !is_legal_tracer {
                return EPERM;
            }
            tracee_inner.tracer = None;
            tracee_inner.trace_stopped = false;
            let mut tracer_inner = tracer_process.inner_exclusive_access();
            tracer_inner.tracees.retain(|t| !Arc::ptr_eq(t, &tracee_process));
            let signal = SignalFlags::from_bits(data as u32).unwrap_or(SignalFlags::empty());
            if !signal.is_empty() {
                tracee_inner.signals.insert(signal);
            }
            if let Some(Some(main_task)) = tracee_inner.tasks.get(0) {
                let mut task_inner = main_task.inner_exclusive_access();
                if task_inner.task_status == TaskStatus::Blocked {
                    task_inner.task_status = TaskStatus::Ready;
                    add_task_to_ready_queue(main_task.clone());
                }
            }
            0
        }
        _ => {
            warn!("Unsupported ptrace request: {}", trace_request);
            -1
        }
    }
}