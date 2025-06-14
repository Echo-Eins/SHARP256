use thiserror::Error;

#[derive(Debug, Error)]
pub enum NatError {
    #[error("transient NAT failure: {0}")]
    Transient(String),
    #[error("permanent NAT failure: {0}")]
    Permanent(String),
}

pub type NatResult<T> = Result<T, NatError>;

impl From<anyhow::Error> for NatError {
    fn from(e: anyhow::Error) -> Self {
        NatError::transient(e.to_string())
    }
}

impl NatError {
    pub fn transient<E: std::fmt::Display>(e: E) -> Self {
        Self::Transient(e.to_string())
    }
    pub fn permanent<E: std::fmt::Display>(e: E) -> Self {
        Self::Permanent(e.to_string())
    }
    pub fn is_transient(&self) -> bool {
        matches!(self, NatError::Transient(_))
    }
    pub fn is_permanent(&self) -> bool {
        matches!(self, NatError::Permanent(_))
    }
}