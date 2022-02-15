use std::fs::File;
use std::{os::unix::prelude::CommandExt, io::ErrorKind};
use std::process::{Command, Child};
use std::io::Write;

use itertools::Itertools;
use libc::pid_t;
use nix::sys::{ptrace, personality, signal::Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::errno::Errno;
use nix::unistd::Pid;
use nix::sched::{sched_setaffinity, CpuSet};
use crate::analysis_session::AnalysisSession;
use crate::capture_filter::CaptureFilter;
use crate::capture_session::CaptureSession;
use crate::hive::HoneyBeeHive;

use std::time::{SystemTime, UNIX_EPOCH};

fn get_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

fn io_error(e: Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e as i32)
}
fn spawn_suspended(cmd: &Command) -> Result<Child, std::io::Error> {
    unsafe {
        cmd.pre_exec(|| {
            ptrace::traceme().map_err(io_error)?;
            let old_personality = personality::get().map_err(io_error )?;
            personality::set(old_personality.union(personality::Persona::ADDR_NO_RANDOMIZE))?;
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    let child_pid = child.id();
    let res = waitpid(Pid::from_raw(child_pid as i32), None);
    match res {
        Ok(WaitStatus::Stopped(waited_pid, Signal::SIGTRAP)) => {
            assert!(child_pid == child.id(), "Got SIGTRAP from the wrong process?? child_pid={}, got pid={}", child_pid, waited_pid);
            Ok(child)
        },
        other => Err(
            std::io::Error::new(
                ErrorKind::Other,
                format!("Got incorrect child status: {:?}", other),
            ))
    }
}

fn pin_process_to_cpu(pid: u32, cpu: u16) {
    let mut cpuset = CpuSet::new();
    cpuset.set(cpu as usize).expect("Could not set CPU in set?");
    sched_setaffinity(Pid::from_raw(pid as pid_t), &cpuset).expect("Could not set cpu affinity??");
}

fn err_str(e: impl ToString) -> String {
    e.to_string()
}

// fn suspend_process(pid: u32) {
//     ptrace::interrupt(Pid::from_raw(pid as i32)).expect("Could not interrupt child process!");
// }

fn unsuspend_process(pid: u32) {
    ptrace::cont(Pid::from_raw(pid as i32), None).expect("Could not continue child process!");
}

fn append_to_file(path: &str, content: &str) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
    write!(file, "{}", content).unwrap();
}

struct TracingTask {
    cmd: Command,
    filters: Vec<CaptureFilter>,
    slide: usize,
}

struct PtTracer {
    tracing_cpu_id: u16,
    buffer_count: u32,
    page_power: u8,
}

struct PtTrace {
    trace: Vec<u8>,
    trace_slide: u64,
}

impl PtTracer {
    fn trace(&self, task: TracingTask, f: impl FnMut(u64)) -> PtTrace {
        assert!(task.filters.len() <= 4);
        let filters = task.filters
            .iter()
            .filter(|x| x.enabled != 0)
            .sorted_by_key(|f| (f.start, f.stop))
            .collect::<Vec<_>>();
        let trace_slide = filters.iter().map(|f|f.start).min().expect("At least one enabled filter is required!");

        let mut capture_session = CaptureSession::new(self.tracing_cpu_id).expect("Could not start capture session");
        capture_session.set_global_buffer_size(self.buffer_count, self.page_power).expect("Could not set global buffer sizes");

        let mut child = spawn_suspended(&task.cmd).expect("Could not spawn child process");
        pin_process_to_cpu(child.id(), self.tracing_cpu_id);

        capture_session.configure_tracing(child.id(), &task.filters[..]).expect("Could not configure tracing!");
        capture_session.set_trace_enable(true, true).expect("Could not enable tracing!");

        unsuspend_process(child.id());
        child.wait().expect("Failed to wait for child pid!");

        capture_session.set_trace_enable(false, false).expect("Could not disable trace after child exited");
        let trace = capture_session.get_trace().expect("Could not retrieve trace!");
        PtTrace {
            trace,
            trace_slide
        }
    }
}



fn trace_pt(hive: HoneyBee_Hive) -> Result<(), String> {
    // CAPTURE

    let mut analysis_session = AnalysisSession::new(hive).expect("Could not create analysis session!");
    analysis_session.reconfigure_with_terminated_trace_buffer(
        trace,
        filter.start.try_into().unwrap()
    ).expect("Failed to reconfigure analysis session");

    analysis_session.decode_with_callback(|block| {
        cov.record_block(block.try_into().unwrap())
    }).expect("Could not decode trace");
    Ok(())
}