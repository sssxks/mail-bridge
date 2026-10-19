//! IMAP/SMTP transport, MIME rendering and multi-account mail operations.
pub mod backend;
pub mod bounded_io;
pub mod command;
mod draft;
pub mod imap;
pub mod mime;
pub mod page;
pub mod service;
mod smtp;
