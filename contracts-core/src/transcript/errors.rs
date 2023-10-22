//! Transcript error types and conversions.

/// Errors stemming from transcript operations
#[derive(Debug)]
pub enum TranscriptError {
    /// An error that occured while serializing a value into the transcript
    Serialization,
}
