use std::fmt;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    JwtInvalidClaims,
    JwtDecodingKey,
    JwtMissingKid,
    JwksMissingKid,
    MissingArgument,
    ContextMissingUsername,
    ContextMissingPassword,
    ContextSelection,
    ContextNotFound,
    ContextAlreadyExists,
    InvalidParentPath,
    ContextNameRequired,
    InvalidConfigDir,
    NoStdin,
    Any(anyhow::Error),
}

impl Error {
    pub fn msg<T>(msg: T) -> Self
    where
        T: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        Self::Any(anyhow::Error::msg(msg))
    }
}

impl<E> From<E> for Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn from(value: E) -> Self {
        Self::Any(anyhow::Error::from(value))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::JwtInvalidClaims => "token invalid claims",
            Self::JwtDecodingKey => "failed to build decoding key",
            Self::JwtMissingKid => "missing kid from token header",
            Self::JwksMissingKid => "jwks does not contain requested kid",
            Self::MissingArgument => "missing argument",
            Self::ContextMissingUsername => "missing username",
            Self::ContextMissingPassword => "missing password",
            Self::ContextSelection => "failed to select context",
            Self::ContextNotFound => "context not found",
            Self::ContextAlreadyExists => "context already exists",
            Self::InvalidParentPath => "invalid parent path",
            Self::ContextNameRequired => "context name required",
            Self::InvalidConfigDir => "invalid OS config dir",
            Self::NoStdin => "no stdin available",
            Self::Any(error) => {
                return error.fmt(f);
            }
        };

        write!(f, "{msg}")
    }
}
