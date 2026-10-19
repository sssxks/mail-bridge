//! IMAP/SMTP transport, MIME rendering and multi-account mail operations.
/// Implementation of backend within this crate.
pub mod backend;
/// Implementation of bounded io within this crate.
pub mod bounded_io;
/// Implementation of command within this crate.
pub mod command;
/// Implementation of draft within this crate.
mod draft;
/// Implementation of imap within this crate.
pub mod imap;
/// Implementation of mime within this crate.
pub mod mime;
/// Implementation of page within this crate.
pub mod page;
/// Implementation of service within this crate.
pub mod service;
/// Implementation of smtp within this crate.
mod smtp;
