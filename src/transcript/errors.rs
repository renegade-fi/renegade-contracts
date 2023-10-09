//! Transcript error types and conversions.

#[derive(Debug)]
pub enum TranscriptError {
    SerializationError(ark_serialize::SerializationError),
}

impl From<ark_serialize::SerializationError> for TranscriptError {
    fn from(value: ark_serialize::SerializationError) -> Self {
        TranscriptError::SerializationError(value)
    }
}
