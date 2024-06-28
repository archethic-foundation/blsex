#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    /// Cryptographic invalidity
    InvalidSignature,
    /// Invalid Point
    InvalidPoint,
    ZeroSizedInput,
}
