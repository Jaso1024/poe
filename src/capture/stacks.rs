use std::collections::HashMap;
use std::io;
use std::sync::mpsc;

use anyhow::Result;

use crate::events::types::*;

const PERF_MMAP_PAGES: usize = 16;

const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
const PERF_SAMPLE_TID: u64 = 1 << 1;
const PERF_SAMPLE_TIME: u64 = 1 << 2;
const PERF_SAMPLE_CALLCHAIN: u64 = 1 << 5;
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;

#[repr(C)]
#[derive(Clone)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events_or_watermark: u32,
    bp_type: u32,
    bp_addr_or_config1: u64,
    bp_len_or_config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    __reserved_2: u16,
    aux_sample_size: u32,
    __reserved_3: u32,
    sig_data: u64,
}

#[repr(C)]
struct PerfEventMmapPage {
    version: u32,
    compat_version: u32,
    lock: u32,
    index: u32,
    offset: i64,
    time_enabled: u64,
    time_running: u64,
    capabilities: u64,
    pmc_width: u16,
    time_shift: u16,
    time_mult: u32,
    time_offset: u64,
    time_zero: u64,
    size: u32,
    _reserved1: u32,
    _reserved2: u64,
    data_head: u64,
    data_tail: u64,
    data_offset: u64,
    data_size: u64,
}

#[repr(C)]
struct PerfEventHeader {
    type_: u32,
    misc: u16,
    size: u16,
}

const PERF_RECORD_SAMPLE: u32 = 9;

struct PerfEventFd {
    fd: i32,
    mmap_base: *mut u8,
    mmap_size: usize,
    pid: i32,
}

unsafe impl Send for PerfEventFd {}

impl Drop for PerfEventFd {
    fn drop(&mut self) {
        if !self.mmap_base.is_null() {
            unsafe {
                libc::munmap(self.mmap_base as *mut libc::c_void, self.mmap_size);
            }
        }
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

pub struct StackSampler {
    events: HashMap<i32, PerfEventFd>,
    base_ts: u64,
    sample_freq: u64,
}

impl StackSampler {
    pub fn new(base_ts: u64, sample_freq: u64) -> Self {
        Self {
            events: HashMap::new(),
            base_ts,
            sample_freq,
        }
    }

    pub fn add_process(&mut self, pid: i32) -> Result<()> {
        if self.events.contains_key(&pid) {
            return Ok(());
        }

        match create_perf_event(pid, self.sample_freq) {
            Ok(perf_fd) => {
                self.events.insert(pid, perf_fd);
                Ok(())
            }
            Err(_) => Ok(()),
        }
    }

    pub fn drain_samples(&mut self, event_tx: &mpsc::Sender<TraceEvent>) -> usize {
        let mut total = 0;

        for (&pid, perf_fd) in &mut self.events {
            let samples = read_perf_samples(perf_fd, self.base_ts);
            for sample in &samples {
                let _ = event_tx.send(TraceEvent::Stack(StackSample {
                    ts: sample.ts,
                    proc_id: pid,
                    frames: sample.ips.clone(),
                }));
            }
            total += samples.len();
        }

        total
    }

    pub fn stop(&mut self) {
        for (_, perf_fd) in &self.events {
            unsafe {
                libc::ioctl(perf_fd.fd, PERF_EVENT_IOC_DISABLE, 0);
            }
        }
    }
}

struct RawSample {
    ts: u64,
    ips: Vec<u64>,
}

fn create_perf_event(pid: i32, freq: u64) -> Result<PerfEventFd> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let mmap_size = (1 + PERF_MMAP_PAGES) * page_size;

    let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
    attr.type_ = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
    attr.sample_period_or_freq = freq;
    attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN;

    // flags bitfield: disabled=1, inherit=1, freq=1, exclude_kernel=1, exclude_hv=1
    // Bit layout of perf_event_attr flags (from LSB):
    // bit 0: disabled
    // bit 1: inherit
    // bit 2: pinned
    // bit 3: exclusive
    // bit 4: exclude_user
    // bit 5: exclude_kernel
    // bit 6: exclude_hv
    // bit 7: exclude_idle
    // bit 8: mmap
    // bit 9: comm
    // bit 10: freq
    attr.flags = (1 << 0)   // disabled
               | (1 << 1)   // inherit
               | (1 << 5)   // exclude_kernel
               | (1 << 6)   // exclude_hv
               | (1 << 10); // freq

    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const PerfEventAttr,
            pid,
            -1i32,
            -1i32,
            0u64,
        )
    } as i32;

    if fd < 0 {
        let err = io::Error::last_os_error();
        anyhow::bail!("perf_event_open failed: {}", err);
    }

    let mmap_base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mmap_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };

    if mmap_base == libc::MAP_FAILED {
        unsafe { libc::close(fd) };
        let err = io::Error::last_os_error();
        anyhow::bail!("mmap for perf ring buffer failed: {}", err);
    }

    unsafe {
        libc::ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    }

    Ok(PerfEventFd {
        fd,
        mmap_base: mmap_base as *mut u8,
        mmap_size,
        pid,
    })
}

fn read_perf_samples(perf_fd: &mut PerfEventFd, base_ts: u64) -> Vec<RawSample> {
    let mut samples = Vec::new();

    if perf_fd.mmap_base.is_null() {
        return samples;
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let data_offset = page_size;
    let data_size = PERF_MMAP_PAGES * page_size;

    let header = unsafe { &*(perf_fd.mmap_base as *const PerfEventMmapPage) };

    let head = unsafe { std::ptr::read_volatile(&header.data_head) };
    std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
    let tail = header.data_tail;

    if head == tail {
        return samples;
    }

    let data_base = unsafe { perf_fd.mmap_base.add(data_offset) };
    let mut cursor = tail;

    while cursor < head {
        let offset = (cursor as usize) % data_size;

        let ev_header = unsafe {
            let ptr = data_base.add(offset);
            if offset + std::mem::size_of::<PerfEventHeader>() > data_size {
                break;
            }
            &*(ptr as *const PerfEventHeader)
        };

        let record_size = ev_header.size as usize;
        if record_size == 0 || record_size > data_size {
            break;
        }

        if ev_header.type_ == PERF_RECORD_SAMPLE {
            if let Some(sample) = parse_sample_record(data_base, offset, record_size, data_size, base_ts) {
                samples.push(sample);
            }
        }

        cursor += record_size as u64;
    }

    unsafe {
        let header_mut = &mut *(perf_fd.mmap_base as *mut PerfEventMmapPage);
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        std::ptr::write_volatile(&mut header_mut.data_tail, head);
    }

    samples
}

fn parse_sample_record(
    data_base: *mut u8,
    offset: usize,
    record_size: usize,
    data_size: usize,
    base_ts: u64,
) -> Option<RawSample> {
    let header_size = std::mem::size_of::<PerfEventHeader>();

    let mut record_data = vec![0u8; record_size];
    for i in 0..record_size {
        let pos = (offset + i) % data_size;
        record_data[i] = unsafe { *data_base.add(pos) };
    }

    let body = &record_data[header_size..];

    if body.len() < 16 {
        return None;
    }

    let _pid = u32::from_ne_bytes(body[0..4].try_into().ok()?);
    let _tid = u32::from_ne_bytes(body[4..8].try_into().ok()?);
    let time = u64::from_ne_bytes(body[8..16].try_into().ok()?);

    let ts = time.saturating_sub(base_ts);

    if body.len() < 24 {
        return None;
    }

    let nr = u64::from_ne_bytes(body[16..24].try_into().ok()?);

    if nr > 256 {
        return None;
    }

    let ips_start = 24;
    let mut ips = Vec::with_capacity(nr as usize);
    for i in 0..nr as usize {
        let ip_offset = ips_start + i * 8;
        if ip_offset + 8 > body.len() {
            break;
        }
        let ip = u64::from_ne_bytes(body[ip_offset..ip_offset + 8].try_into().ok()?);
        if ip != 0 {
            ips.push(ip);
        }
    }

    Some(RawSample { ts, ips })
}
