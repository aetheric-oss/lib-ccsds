//! <center>
//! <img src="https://github.com/Arrow-air/tf-github/raw/main/src/templates/doc-banner-services.png" style="height:250px" />
//! </center>
//! <div align="center">
//!     <a href="https://github.com/Arrow-air/lib-ccsds/releases">
//!         <img src="https://img.shields.io/github/v/release/Arrow-air/lib-ccsds?include_prereleases" alt="GitHub release (latest by date including pre-releases)">
//!     </a>
//!     <a href="https://github.com/Arrow-air/lib-ccsds/tree/main">
//!         <img src="https://github.com/arrow-air/lib-ccsds/actions/workflows/rust_ci.yml/badge.svg?branch=main" alt="Rust Checks">
//!     </a>
//!     <a href="https://discord.com/invite/arrow">
//!         <img src="https://img.shields.io/discord/853833144037277726?style=plastic" alt="Arrow DAO Discord">
//!     </a>
//!     <br><br>
//! </div>
//!
//! Implementations of telemetry and command packet standards.
//!
//! # Features
//! `std`: (Default) enable import into `std` projects.
//!
//! # `no_std` Support
//! In embedded rust projects, specify `default-features=false` for
//!  the `lib_ccsds` dependency to import the `no_std` crate.
#![cfg_attr(not(feature = "std"), no_std)]

pub mod arrow;
pub mod ccsds;
pub mod error;
pub mod time;
