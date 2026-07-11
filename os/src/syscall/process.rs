//! Process management syscalls
use crate::config::PAGE_SIZE;
use crate::mm::{translated_byte_buffer, MapPermission, PageTable, PTEFlags, VirtAddr};
use crate::task::{
    change_current_mmap, change_current_munmap, change_program_brk, current_user_token,
    exit_current_and_run_next, get_current_syscall_times, suspend_current_and_run_next,
};
use crate::timer::get_time_us;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

const TRACE_READ: usize = 0;
const TRACE_WRITE: usize = 1;
const TRACE_SYSCALL: usize = 2;

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// get time with second and microsecond
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let timeval = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let src = unsafe {
        core::slice::from_raw_parts(
            &timeval as *const TimeVal as *const u8,
            core::mem::size_of::<TimeVal>(),
        )
    };
    let buffers = translated_byte_buffer(current_user_token(), ts as *const u8, src.len());
    let mut offset = 0;
    for buffer in buffers {
        let len = buffer.len();
        buffer.copy_from_slice(&src[offset..offset + len]);
        offset += len;
    }
    0
}

/// trace syscall
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    match trace_request {
        TRACE_READ => read_user_byte(id).map_or(-1, |byte| byte as isize),
        TRACE_WRITE => {
            if write_user_byte(id, data as u8) {
                0
            } else {
                -1
            }
        }
        TRACE_SYSCALL => get_current_syscall_times(id),
        _ => -1,
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    if start % PAGE_SIZE != 0 || len == 0 || port == 0 || (port & !0x7) != 0 {
        return -1;
    }

    let mut perm = MapPermission::U;

    if port & 0x1 != 0 {
        perm |= MapPermission::R;
    }
    if port & 0x2 != 0 {
        perm |= MapPermission::W;
    }
    if port & 0x4 != 0 {
        perm |= MapPermission::X;
    }

    change_current_mmap(start, len, perm)
}
// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    if start % PAGE_SIZE != 0 || len == 0 {
        return -1;
    }
    change_current_munmap(start, len)
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

fn read_user_byte(addr: usize) -> Option<u8> {
    let page_table = PageTable::from_token(current_user_token());
    let va = VirtAddr::from(addr);
    let pte = page_table.translate(va.floor())?;
    let flags = pte.flags();
    if !pte.is_valid() || !pte.readable() || !flags.contains(PTEFlags::U) {
        return None;
    }
    Some(pte.ppn().get_bytes_array()[va.page_offset()])
}

fn write_user_byte(addr: usize, data: u8) -> bool {
    let page_table = PageTable::from_token(current_user_token());
    let va = VirtAddr::from(addr);
    let Some(pte) = page_table.translate(va.floor()) else {
        return false;
    };
    let flags = pte.flags();
    if !pte.is_valid() || !pte.writable() || !flags.contains(PTEFlags::U) {
        return false;
    }
    pte.ppn().get_bytes_array()[va.page_offset()] = data;
    true
}