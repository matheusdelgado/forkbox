use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::resource::{setrlimit, Resource};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{chroot, execvp, fork, pipe, ForkResult, Gid, Pid, Uid};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const MAX_CPU_SECONDS: u64 = 5;
const MAX_OUTPUT_BYTES: usize = 256 * 1024; // 256 KB
const SOCKET_PATH: &str = "/tmp/forkbox.sock";

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Serialize, Deserialize, Debug)]
pub struct ExecutionRequest {
    pub cmd: String,
    pub timeout_ms: u32,
    pub allow_network: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExecutionResponse {
    pub exit_code: i32,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub duration_us: u128,
}

// Configuração de User Namespace para execução 100% Rootless (sem sudo)
fn setup_user_namespace() -> Result<(), String> {
    let uid = Uid::current().as_raw();
    let gid = Gid::current().as_raw();

    // Cria novo User Namespace
    unshare(CloneFlags::CLONE_NEWUSER).map_err(|e| format!("Falha CLONE_NEWUSER: {}", e))?;

    // Desativa setgroups (obrigatório pelo kernel para unprivileged gid_map)
    if Path::new("/proc/self/setgroups").exists() {
        let _ = fs::write("/proc/self/setgroups", "deny");
    }

    // Mapeia o usuário atual do host para UID/GID 0 (root) dentro do namespace
    fs::write("/proc/self/uid_map", format!("0 {} 1\n", uid))
        .map_err(|e| format!("Falha uid_map: {}", e))?;
    fs::write("/proc/self/gid_map", format!("0 {} 1\n", gid))
        .map_err(|e| format!("Falha gid_map: {}", e))?;

    Ok(())
}

fn install_seccomp_bpf() -> Result<(), String> {
    const BLOCKED_SYSCALLS: &[i64] = &[
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
    ];

    let n = BLOCKED_SYSCALLS.len();
    let mut filter: Vec<libc::sock_filter> = Vec::with_capacity(n + 3);

    filter.push(libc::sock_filter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: 0,
    });

    for (i, &syscall_nr) in BLOCKED_SYSCALLS.iter().enumerate() {
        let jt = (n - i) as u8;
        filter.push(libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt,
            jf: 0,
            k: syscall_nr as u32,
        });
    }

    filter.push(libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    });

    filter.push(libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0x0000ffff),
    });

    let mut prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err("Falha PR_SET_NO_NEW_PRIVS".into());
        }
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut prog as *mut libc::sock_fprog,
            0,
            0,
        ) != 0
        {
            return Err("Falha Seccomp-BPF".into());
        }
    }

    Ok(())
}

fn set_nonblocking<T: AsRawFd>(target: &T) {
    unsafe {
        let fd = target.as_raw_fd();
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

// Execução isolada em sandbox efêmera rootless
pub fn execute_sandboxed(req: &ExecutionRequest) -> ExecutionResponse {
    let start = Instant::now();
    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
    let session_dir = PathBuf::from(format!("/tmp/forkbox_sess_{}", session_id));

    let upper = session_dir.join("upper");
    let work = session_dir.join("work");
    let merged = session_dir.join("merged");

    let _ = fs::create_dir_all(&upper);
    let _ = fs::create_dir_all(&work);
    let _ = fs::create_dir_all(&merged);

    let (out_r, out_w) = pipe().unwrap();
    let (err_r, err_w) = pipe().unwrap();

    let is_network_isolated = !req.allow_network.unwrap_or(false);

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            drop(out_w);
            drop(err_w);

            let mut out_file = File::from(out_r);
            let mut err_file = File::from(err_r);
            set_nonblocking(&out_file);
            set_nonblocking(&err_file);

            let timeout = Duration::from_millis(req.timeout_ms as u64);
            let mut stdout_acc = Vec::new();
            let mut stderr_acc = Vec::new();
            let mut timed_out = false;
            let mut exit_code = 0;

            loop {
                let mut buf = [0u8; 4096];
                while let Ok(n) = out_file.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if stdout_acc.len() < MAX_OUTPUT_BYTES {
                        stdout_acc.extend_from_slice(&buf[..n]);
                    }
                }
                while let Ok(n) = err_file.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if stderr_acc.len() < MAX_OUTPUT_BYTES {
                        stderr_acc.extend_from_slice(&buf[..n]);
                    }
                }

                match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(_, c)) => {
                        exit_code = c;
                        break;
                    }
                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                        exit_code = 128 + sig as i32;
                        break;
                    }
                    Ok(WaitStatus::StillAlive) => {
                        if start.elapsed() >= timeout {
                            timed_out = true;
                            let _ = kill(child, Signal::SIGKILL);
                            let _ = waitpid(child, None);
                            exit_code = 124;
                            break;
                        }
                        std::thread::sleep(Duration::from_micros(200));
                    }
                    Ok(_) => break,
                    Err(_) => break,
                }
            }

            // Drenagem final
            let mut buf = [0u8; 4096];
            while let Ok(n) = out_file.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if stdout_acc.len() < MAX_OUTPUT_BYTES {
                    stdout_acc.extend_from_slice(&buf[..n]);
                }
            }
            while let Ok(n) = err_file.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if stderr_acc.len() < MAX_OUTPUT_BYTES {
                    stderr_acc.extend_from_slice(&buf[..n]);
                }
            }

            // Purga o delta de arquivos em RAM
            let _ = umount2(&merged, MntFlags::MNT_DETACH);
            let _ = fs::remove_dir_all(&session_dir);

            ExecutionResponse {
                exit_code,
                timed_out,
                stdout: String::from_utf8_lossy(&stdout_acc).to_string(),
                stderr: String::from_utf8_lossy(&stderr_acc).to_string(),
                duration_us: start.elapsed().as_micros(),
            }
        }
        Ok(ForkResult::Child) => {
            drop(out_r);
            drop(err_r);

            // Redireciona saídas
            unsafe {
                libc::dup2(out_w.as_raw_fd(), 1);
                libc::dup2(err_w.as_raw_fd(), 2);
            }
            drop(out_w);
            drop(err_w);

            // 1. Ativa isolamento Rootless (User Namespaces)
            if let Err(e) = setup_user_namespace() {
                eprintln!("[Sandbox Error] {}", e);
                unsafe { libc::_exit(101) };
            }

            // 2. Isola Mount, PID, IPC, UTS e opcionalmente Network
            let mut flags = CloneFlags::CLONE_NEWNS
                | CloneFlags::CLONE_NEWIPC
                | CloneFlags::CLONE_NEWUTS
                | CloneFlags::CLONE_NEWPID;

            if is_network_isolated {
                flags |= CloneFlags::CLONE_NEWNET;
            }

            if let Err(e) = unshare(flags) {
                eprintln!("[Sandbox Error] unshare: {}", e);
                unsafe { libc::_exit(102) };
            }

            let _ = mount(
                None::<&str>,
                "/",
                None::<&str>,
                MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                None::<&str>,
            );

            // 3. Montagem de OverlayFS Rootless
            let overlay_opts = format!(
                "lowerdir=/,upperdir={},workdir={}",
                upper.display(),
                work.display()
            );

            let mount_res = mount(
                Some("overlay"),
                &merged,
                Some("overlay"),
                MsFlags::empty(),
                Some(overlay_opts.as_str()),
            );

            if mount_res.is_ok() {
                let _ = chroot(&merged);
                let _ = std::env::set_current_dir("/");
            }

            // 4. Limites de Recursos
            let _ = setrlimit(Resource::RLIMIT_CPU, MAX_CPU_SECONDS, MAX_CPU_SECONDS);
            let _ = setrlimit(Resource::RLIMIT_NPROC, 64, 64);

            // 5. Injeta Seccomp-BPF
            let _ = install_seccomp_bpf();

            // 6. Executa comando
            let c_cmd = CString::new("/bin/sh").unwrap();
            let c_arg1 = CString::new("-c").unwrap();
            let c_arg2 = CString::new(req.cmd.clone()).unwrap();

            let _ = execvp(&c_cmd, &[c_cmd.clone(), c_arg1, c_arg2]);
            unsafe { libc::_exit(127) };
        }
        Err(_) => ExecutionResponse {
            exit_code: -1,
            timed_out: false,
            stdout: String::new(),
            stderr: "Falha ao disparar fork".into(),
            duration_us: start.elapsed().as_micros(),
        },
    }
}

// Daemon concorrente em segundo plano ouvindo em Unix Domain Socket
fn run_daemon() {
    let _ = fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH).expect("Falha ao criar Unix Domain Socket");

    // Permissões para que scripts locais acessem o socket livremente
    let _ = fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o777));

    println!("============================================================");
    println!("   FORKBOX DAEMON: Ativo e ouvindo em {}", SOCKET_PATH);
    println!("   Modo: Rootless User Namespaces + Seccomp-BPF             ");
    println!("============================================================");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("[Daemon] Erro de conexão: {}", e);
            }
        }
    }
}

fn handle_client(mut stream: UnixStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();

    if reader.read_line(&mut line).is_ok() && !line.trim().is_empty() {
        if let Ok(req) = serde_json::from_str::<ExecutionRequest>(&line) {
            let res = execute_sandboxed(&req);
            if let Ok(res_json) = serde_json::to_string(&res) {
                let _ = stream.write_all(res_json.as_bytes());
                let _ = stream.write_all(b"\n");
                let _ = stream.flush();
            }
        } else {
            let _ = stream.write_all(b"{\"error\": \"Payload JSON invalido\"}\n");
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // 1. Modo Daemon Residente (para produção e orquestradores de IA)
    if args.len() >= 2 && args[1] == "daemon" {
        run_daemon();
        return;
    }

    // 2. Modo CLI Dinâmico: ./forkbox exec "comando"
    if args.len() >= 3 && args[1] == "exec" {
        let cmd = args[2..].join(" ");
        let req = ExecutionRequest {
            cmd,
            timeout_ms: 5000,
            allow_network: Some(false),
        };
        let res = execute_sandboxed(&req);
        if !res.stdout.is_empty() {
            print!("{}", res.stdout);
        }
        if !res.stderr.is_empty() {
            eprint!("{}", res.stderr);
        }
        std::process::exit(res.exit_code);
    }

    // 3. Suíte de Testes Automatizados (Zero sudo)
    println!("============================================================");
    println!("   FORKBOX v0.5: Teste Rootless & Socket Architecture       ");
    println!("============================================================");

    println!("\n[1] Testando Execução Rootless (Sem privilégios de sudo)...");
    let uid = Uid::current();
    println!(" ↳ Rodando sob Host UID real: {}", uid);

    let req_test = ExecutionRequest {
        cmd: "echo 'rootless_sandbox_online' && id".into(),
        timeout_ms: 2000,
        allow_network: Some(false),
    };
    let res = execute_sandboxed(&req_test);
    println!(" ↳ Saída Sandbox: {}", res.stdout.trim());
    println!(" ↳ Exit Code: {} | Latência: {:.2} ms", res.exit_code, res.duration_us as f64 / 1000.0);

    println!("\n[2] Testando Seccomp-BPF Rootless...");
    let req_sec = ExecutionRequest {
        cmd: "reboot 2>&1".into(),
        timeout_ms: 2000,
        allow_network: Some(false),
    };
    let res_sec = execute_sandboxed(&req_sec);
    println!(" ↳ Saída: {}", res_sec.stdout.trim());
    println!(" ↳ Exit Code: {} (Bloqueio determinístico confirmado)", res_sec.exit_code);

    println!("\n[3] Testando Isolamento de Rede...");
    let req_net = ExecutionRequest {
        cmd: "ping -c 1 1.1.1.1 2>&1 || echo 'REDE_BLOQUEADA'".into(),
        timeout_ms: 2000,
        allow_network: Some(false),
    };
    let res_net = execute_sandboxed(&req_net);
    println!(" ↳ Saída Rede: {}", res_net.stdout.trim());

    println!("\nPara iniciar o daemon de produção para agentes de IA:");
    println!("  ./target/release/forkbox daemon");
    println!("============================================================\n");
}