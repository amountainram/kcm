use std::fmt;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    // resources
    Conflict,
    NotFound,

    // daemon
    TcpListenerBind,
    ResponseError,

    // cli
    InvalidPublicKey,
    MustLogin,
    MissingCredentials,
    AuthNoTokenFound,
    JwtInvalidClaims,
    JwtDecodingKey,
    JwtMissingKid,
    JwksMissingKid,
    TooManyArguments,
    MissingArgument,
    ContextMissingServerUrl,
    ContextMissingUsername,
    ContextMissingPassword,
    ContextSelection,
    ContextNotFound,
    ContextAlreadyExists,
    InvalidParentPath,
    ContextNameRequired,
    InvalidConfigDir,
    NoStdin,
    FileExists,
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
            Self::Conflict => "conflict",
            Self::NotFound => "not found",
            Self::TcpListenerBind => "tcp listener bind",
            Self::ResponseError => "response error",
            Self::InvalidPublicKey => "invalid public key",
            Self::FileExists => "file exists",
            Self::MustLogin => "must login",
            Self::MissingCredentials => "missing credentials",
            Self::AuthNoTokenFound => "no token found",
            Self::JwtInvalidClaims => "token invalid claims",
            Self::JwtDecodingKey => "failed to build decoding key",
            Self::JwtMissingKid => "missing kid from token header",
            Self::JwksMissingKid => "jwks does not contain requested kid",
            Self::TooManyArguments => "too many arguments",
            Self::MissingArgument => "missing argument",
            Self::ContextMissingServerUrl => "missing server-url",
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
