//! Transcript error types and conversions.

/// Errors stemming from transcript operations
#[derive(Debug)]
pub enum TranscriptError {
    /// An error that occured while serializing a value into the transcript
    Serialization,
}

impl From<ark_serialize::SerializationError> for TranscriptError {
    fn from(_value: ark_serialize::SerializationError) -> Self {
        TranscriptError::Serialization
    }
}
