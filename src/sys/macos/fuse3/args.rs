// mount options handed to libfuse, built as the argv a fuse program would receive

use std::ffi::CString;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    FsKit,
    Kext,
}

#[derive(Clone, Debug)]
pub struct MountOpts {
    pub volname: String,
    pub allow_other: bool,
    pub daemon_timeout: u32,
    pub iosize: u32,
}

fn c_arg(s: &str) -> CString {
    CString::new(s.replace('\0', "_")).unwrap_or_default()
}

// commas would split the option and a nul would end the argument
fn clean_volname(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| if c == ',' || c == '\0' { '_' } else { c })
        .collect();
    if clean.is_empty() {
        "csync".to_owned()
    } else {
        clean
    }
}

pub(super) fn mount_args(opts: &MountOpts, backend: Backend) -> Vec<CString> {
    let mut options = format!(
        "fsname=csync,volname={},default_permissions,nodev,nosuid,noatime,noappledouble,noapplexattr,nobrowse,iosize={},daemon_timeout={}",
        clean_volname(&opts.volname),
        opts.iosize,
        opts.daemon_timeout
    );
    if opts.allow_other {
        options.push_str(",allow_other");
    }
    // TRACE diagnostics, never to be merged
    if let Ok(extra) = std::env::var("CSYNC_TRACE_MOUNT_OPTS")
        && !extra.is_empty()
    {
        options.push(',');
        options.push_str(&extra);
        eprintln!("TRACE mount options: {options}");
    }
    let mut args = vec![c_arg("csync")];
    if backend == Backend::FsKit {
        args.push(c_arg("-o"));
        args.push(c_arg("backend=fskit"));
    }
    args.push(c_arg("-o"));
    args.push(c_arg(&options));
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> MountOpts {
        MountOpts {
            volname: "proj".to_owned(),
            allow_other: false,
            daemon_timeout: 60,
            iosize: 1_048_576,
        }
    }

    fn strings(args: &[CString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    const BASE: &str = "fsname=csync,volname=proj,default_permissions,nodev,nosuid,noatime,noappledouble,noapplexattr,nobrowse,iosize=1048576,daemon_timeout=60";

    #[test]
    fn kext_args_carry_only_the_option_string() {
        assert_eq!(
            strings(&mount_args(&opts(), Backend::Kext)),
            ["csync", "-o", BASE]
        );
    }

    #[test]
    fn fskit_args_select_the_backend_first() {
        assert_eq!(
            strings(&mount_args(&opts(), Backend::FsKit)),
            ["csync", "-o", "backend=fskit", "-o", BASE]
        );
    }

    #[test]
    fn allow_other_is_appended_last() {
        let o = MountOpts {
            allow_other: true,
            ..opts()
        };
        let args = strings(&mount_args(&o, Backend::Kext));
        assert_eq!(args[2], format!("{BASE},allow_other"));
    }

    #[test]
    fn the_data_cache_option_is_never_requested() {
        for backend in [Backend::Kext, Backend::FsKit] {
            let joined = strings(&mount_args(&opts(), backend)).join(" ");
            assert!(!joined.contains("auto_cache"));
        }
    }

    #[test]
    fn volume_names_lose_commas_and_nuls() {
        let o = MountOpts {
            volname: "a,b\0c".to_owned(),
            ..opts()
        };
        let args = strings(&mount_args(&o, Backend::Kext));
        assert!(args[2].starts_with("fsname=csync,volname=a_b_c,default_permissions,"));
    }

    #[test]
    fn an_empty_volume_name_falls_back_to_the_project_name() {
        let o = MountOpts {
            volname: String::new(),
            ..opts()
        };
        let args = strings(&mount_args(&o, Backend::Kext));
        assert!(args[2].starts_with("fsname=csync,volname=csync,default_permissions,"));
    }

    #[test]
    fn timeout_and_iosize_come_from_the_options() {
        let o = MountOpts {
            daemon_timeout: 7,
            iosize: 65_536,
            ..opts()
        };
        let args = strings(&mount_args(&o, Backend::Kext));
        assert!(args[2].ends_with("iosize=65536,daemon_timeout=7"));
    }
}
