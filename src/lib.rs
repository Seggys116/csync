#![deny(unsafe_code)]

pub mod bench;
pub mod cli;
pub mod config;
#[cfg(unix)]
pub mod ctl;
pub mod delta;
pub mod doctor;
pub mod merge;
pub mod proto;

pub mod crypto {
    pub mod noise;
    pub mod trust;
}

pub mod net {
    pub mod conn;
    pub mod discover;
    pub mod rpc;
}

pub mod ignore {
    pub mod repo;
    pub mod rules;
}

pub mod index {
    pub mod persist;
    pub mod scan;
    pub mod tree;
}

pub mod guest;
pub mod host;
#[allow(unsafe_code)]
pub mod sys;
pub mod tui;
