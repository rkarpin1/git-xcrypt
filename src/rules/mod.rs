//! What the user declared, and what it decides about one file.
//!
//! [`declaration`] parses `.git-xcrypt`; [`decide`] turns it into the one
//! answer the filter needs — encrypt or pass through — and must stay a pure
//! function of content and declaration, because `lock` depends on it producing
//! exactly the bytes git stores. [`eol`] is the line-ending half of that
//! answer, including the text/binary rule frozen with the file format.

pub mod decide;
pub mod declaration;
pub mod eol;
