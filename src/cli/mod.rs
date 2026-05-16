use crate::{Error, Result, client::oauth2, commands::Sensitive, out};
pub use authorize::AuthorizeCommands;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
pub use bootstrap::{BootstrapAdminPostAction, BootstrapCommands};
pub use clap::Parser;
use clap::{Subcommand, ValueEnum};
pub use clients::ClientsCommands;
pub use completions::{CompletionsCommands, ShellKind};
pub use context::ContextCommands;
use jsonwebtoken::jwk;
use kcm_derive::Completions;
pub use realms::RealmsCommands;
use std::{
    borrow::Cow,
    fmt, fs,
    path::{Path, PathBuf},
};
use tracing::{debug, error, warn};
pub use users::UsersCommands;

mod authorize;
mod bootstrap;
mod clients;
mod completions;
mod context;
mod realms;
mod users;

#[derive(Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    #[value(name = "plain")]
    Plain,
    #[value(name = "json")]
    Json,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Plain => "plain",
                Self::Json => "json",
            }
        )
    }
}

fn print_path(path: &Path) -> Cow<'_, str> {
    String::from_utf8_lossy(path.as_os_str().as_encoded_bytes())
}

fn can_write<'a>(
    path: &'a Path,
    overwrite: bool,
    flag_out: &str,
    flag_overwrite: &str,
) -> Result<&'a Path> {
    let is_path = fs::exists(path)
        .inspect_err(|error| {
            error!(
                %error,
                path = %print_path(path),
                "failed to stat file system path"
            )
        })
        .map_err(Error::from)?;
    let dir = path.parent().ok_or(Error::InvalidParentPath)?;

    if !is_path || overwrite {
        Ok(dir)
    } else {
        out!(
            "file referenced by {flag_out} already exists —  \
                 use \"{flag_overwrite}\" to overwrite"
        );
        Err(Error::FileExists)
    }
}

fn write_file(
    path: &Path,
    overwrite: bool,
    content: &[u8],
    flag_out: &str,
    flag_overwrite: &str,
) -> Result<()> {
    let dir = can_write(path, overwrite, flag_out, flag_overwrite)?;
    fs::create_dir_all(dir).inspect_err(
        |error| error!(path = %print_path(dir), %error, "failed to create file directory"),
    )?;
    fs::write(path, content).inspect_err(|error| {
        error!(
            path = %print_path(path),
            %error,
            "failed to write to file",
        )
    })?;

    Ok(())
}

pub trait WriteOutChecks {
    fn should_write(&self) -> bool;

    fn can_write(&self) -> Result<()>;
}

#[derive(Clone, Parser, Default)]
pub struct JwksManagement {
    /// Dump Jwks keys (if any) content in the given path.
    /// A new file will be created if exists
    #[arg(long = "jwks-out")]
    jwks_out: Option<PathBuf>,
    /// Overwrites the jwks out file if exists
    #[arg(long = "jwks-out-overwrite", default_value = "false")]
    jwks_out_overwrite: bool,
}

impl WriteOutChecks for JwksManagement {
    fn should_write(&self) -> bool {
        self.jwks_out.is_some()
    }

    fn can_write(&self) -> Result<()> {
        let path = match &self.jwks_out {
            Some(path) => path,
            None => {
                return Ok(());
            }
        };

        can_write(
            path,
            self.jwks_out_overwrite,
            "--jwks-out",
            "--jwks-out-overwrite",
        )?;

        Ok(())
    }
}

impl JwksManagement {
    pub fn write_out<T>(&self, content: T) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        let path = match &self.jwks_out {
            Some(path) => path,
            None => {
                return Ok(());
            }
        };

        write_file(
            path,
            self.jwks_out_overwrite,
            content.as_ref(),
            "--jwks-out",
            "--jwks-out-overwrite",
        )?;

        Ok(())
    }
}

#[derive(Clone, Copy, Default, ValueEnum)]
pub enum KeyAlgorithm {
    #[value(name = "rsa", alias = "RSA")]
    Rsa,
    #[value(name = "ec-p256", alias = "EC-P256")]
    ECP256,
    #[value(name = "ec-p384", alias = "EC-P384")]
    ECP384,
    #[default]
    #[value(name = "ed25519", alias = "Ed25519", alias = "ED25519")]
    Ed25519,
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                KeyAlgorithm::Rsa => "rsa",
                KeyAlgorithm::ECP256 => "ec-p256",
                KeyAlgorithm::ECP384 => "ec-p384",
                KeyAlgorithm::Ed25519 => "ed25519",
            }
        )
    }
}

#[derive(Clone, Parser, Default)]
pub struct PrivateKey {
    pub algorithm: KeyAlgorithm,
    out: PathBuf,
    overwrite: bool,
}

impl WriteOutChecks for PrivateKey {
    fn should_write(&self) -> bool {
        true
    }

    fn can_write(&self) -> Result<()> {
        can_write(
            &self.out,
            self.overwrite,
            "--key-out",
            "--key-out-overwrite",
        )?;

        Ok(())
    }
}

#[derive(Clone, Parser, Default)]
pub struct PrivateKeyManagement {
    #[arg(long = "key-algorithm")]
    key_algorithm: Option<KeyAlgorithm>,
    /// Dump a private key (if any) content in the given path.
    /// A new file will be created if exists
    #[arg(long = "key-out")]
    key_out: Option<PathBuf>,
    /// Overwrites the private key out file if exists
    #[arg(long = "key-out-overwrite", default_value = "false")]
    key_out_overwrite: bool,
}

impl PrivateKeyManagement {
    #[allow(unused)]
    pub fn used(&self) -> Vec<&'static str> {
        let mut used = vec![];

        if self.key_out.is_some() {
            used.push("--key-out");
        }

        used
    }
}

#[derive(Parser, Default)]
pub struct KeyPairManagement {
    /// Key ID for the JWK
    #[arg(long = "kid")]
    kid: Option<String>,
    /// Path to a PEM public key
    /// (mutually exclusive with --jwsk-in, --jwks-from-pem, --jwks-url)
    #[arg(long = "pem")]
    pem: Option<PathBuf>,
    /// Path to a JWKS file
    /// (mutually exclusive with --pem, --jwks-from-pem, --jwks-url)
    #[arg(long = "jwks")]
    jwks_in: Option<PathBuf>,
    /// URL to fetch JWKS
    /// (mutually exclusive with --pem, --jwks,  --jwks-from-pem)
    #[arg(long = "jwks-url")]
    jwks_url: Option<String>,
    /// Convert a PEM private key or public key to JWKS
    /// (requires --jwks-out and --kid,
    /// mutually exclusive with --pem, --jwks-from-pem, --jwks-url)
    #[arg(long = "jwks-from-pem")]
    jwks_from_pem: Option<PathBuf>,
    #[command(flatten)]
    jwks_out: JwksManagement,
    #[command(flatten)]
    key_out: PrivateKeyManagement,
}

impl KeyPairManagement {
    pub fn used(&self) -> Vec<&'static str> {
        let mut used = vec![];

        if self.kid.is_some() {
            used.push("--kid");
        }

        if self.pem.is_some() {
            used.push("--pem")
        }

        if self.jwks_from_pem.is_some() {
            used.push("--jwks-from-pem");
        }

        if self.jwks_url.is_some() {
            used.push("--jwks-url");
        }

        used
    }
}

enum PublicKey {
    Rsa(rsa::RsaPublicKey),
    ECP256(p256::PublicKey),
    ECP384(p384::PublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

fn decode_as_public_key(pem_str: &str) -> Result<PublicKey> {
    // Try RSA
    if let Ok(key) = <rsa::RsaPublicKey as rsa::pkcs1::DecodeRsaPublicKey>::from_pkcs1_pem(pem_str)
        .inspect_err(|error| debug!(%error, "failed to parse as pkcs1 pem for RSA public key"))
        .or_else(|_| {
            <rsa::RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_pem(pem_str)
                .inspect_err(
                    |error| debug!(%error, "failed to parse as pkcs8 pem for RSA public key"),
                )
        })
        .or_else(|_| {
            <rsa::RsaPrivateKey as rsa::pkcs1::DecodeRsaPrivateKey>::from_pkcs1_pem(pem_str)
                .map(|pk| pk.to_public_key())
                .inspect_err(
                    |error| debug!(%error, "failed to parse as pkcs1 pem for RSA private key"),
                )
        })
        .or_else(|_| {
            <rsa::RsaPrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(pem_str)
                .map(|pk| pk.to_public_key())
                .inspect_err(
                    |error| debug!(%error, "failed to parse as pkcs8 pem for RSA private key"),
                )
        })
    {
        return Ok(PublicKey::Rsa(key));
    }

    // Try EC P-256
    if let Ok(key) = p256::PublicKey::from_sec1_bytes(pem_str.as_bytes())
        .inspect_err(|error| debug!(%error, "failed to parse as sec1 pem for EC P-256 public key"))
        .or_else(|_| {
            <p256::PublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_pem(pem_str)
                .inspect_err(
                    |error| debug!(%error, "failed to parse as pkcs8 pem for EC P-256 public key"),
                )
        })
        .or_else(|_| {
            p256::SecretKey::from_sec1_pem(pem_str)
                .map(|pk| pk.public_key())
                .inspect_err(
                    |error| debug!(%error, "failed to parse as sec1 pem for EC P-256 private key"),
                )
        })
        .or_else(|_| {
            <p256::SecretKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(pem_str)
                .map(|pk| pk.public_key())
                .inspect_err(
                    |error| debug!(%error, "failed to parse as pkcs8 pem for EC P-256 private key"),
                )
        })
    {
        return Ok(PublicKey::ECP256(key));
    }

    // Try EC P-384
    if let Ok(key) = p384::PublicKey::from_sec1_bytes(pem_str.as_bytes())
        .inspect_err(|error| debug!(%error, "failed to parse as sec1 pem for EC P-384 public key"))
        .or_else(|_| {
            <p384::PublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_pem(pem_str)
                .inspect_err(
                    |error| debug!(%error, "failed to parse as pkcs8 pem for EC P-384 public key"),
                )
        })
        .or_else(|_| {
            p384::SecretKey::from_sec1_pem(pem_str)
                .map(|pk| pk.public_key())
                .inspect_err(
                    |error| debug!(%error, "failed to parse as sec1 pem for EC P-384 private key"),
                )
        })
        .or_else(|_| {
            <p384::SecretKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(pem_str)
                .map(|pk| pk.public_key())
                .inspect_err(
                    |error| debug!(%error, "failed to parse as pkcs8 pem for EC P-384 private key"),
                )
        })
    {
        return Ok(PublicKey::ECP384(key));
    }

    // Try Ed25519
    if let Ok(key) =
        <ed25519_dalek::VerifyingKey as ed25519_dalek::pkcs8::DecodePublicKey>::from_public_key_pem(
            pem_str,
        )
        .inspect_err(|error| debug!(%error, "failed to parse as pkcs8 pem for ED25519 public key"))
        .or_else(|_| {
            <ed25519_dalek::SigningKey as ed25519_dalek::pkcs8::DecodePrivateKey>::from_pkcs8_pem(
                pem_str,
            )
            .map(|pk| pk.verifying_key())
            .inspect_err(
                |error| debug!(%error, "failed to parse as pkcs8 pem for ED25519 private key"),
            )
        })
    {
        return Ok(PublicKey::Ed25519(key));
    }

    Err(Error::msg("unsupported or invalid PEM public key"))
}

fn decode_as_public_key_jwks(pem_str: &str) -> Result<jwk::Jwk> {
    use rsa::traits::PublicKeyParts;
    let common = jwk::CommonParameters {
        public_key_use: Some(jwk::PublicKeyUse::Signature),
        key_operations: Some(vec![jwk::KeyOperations::Verify]),
        ..Default::default()
    };

    let jwks = match decode_as_public_key(pem_str)? {
        PublicKey::Rsa(key) => jwk::Jwk {
            common,
            algorithm: jwk::AlgorithmParameters::RSA(jwk::RSAKeyParameters {
                key_type: jwk::RSAKeyType::RSA,
                n: BASE64_URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
                e: BASE64_URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
            }),
        },
        PublicKey::ECP256(key) => {
            let point = p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&key, false);
            jwk::Jwk {
                common,
                algorithm: jwk::AlgorithmParameters::EllipticCurve(
                    jwk::EllipticCurveKeyParameters {
                        key_type: jwk::EllipticCurveKeyType::EC,
                        curve: jwk::EllipticCurve::P256,
                        x: BASE64_URL_SAFE_NO_PAD.encode(
                            point.x().ok_or(Error::InvalidPublicKey).inspect_err(|_| {
                                error!("malformed public key");
                            })?,
                        ),
                        y: BASE64_URL_SAFE_NO_PAD.encode(
                            point.y().ok_or(Error::InvalidPublicKey).inspect_err(|_| {
                                error!("malformed public key");
                            })?,
                        ),
                    },
                ),
            }
        }
        PublicKey::ECP384(key) => {
            let point = p384::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&key, false);
            jwk::Jwk {
                common,
                algorithm: jwk::AlgorithmParameters::EllipticCurve(
                    jwk::EllipticCurveKeyParameters {
                        key_type: jwk::EllipticCurveKeyType::EC,
                        curve: jwk::EllipticCurve::P384,
                        x: BASE64_URL_SAFE_NO_PAD.encode(
                            point.x().ok_or(Error::InvalidPublicKey).inspect_err(|_| {
                                error!("malformed public key");
                            })?,
                        ),
                        y: BASE64_URL_SAFE_NO_PAD.encode(
                            point.y().ok_or(Error::InvalidPublicKey).inspect_err(|_| {
                                error!("malformed public key");
                            })?,
                        ),
                    },
                ),
            }
        }
        PublicKey::Ed25519(key) => jwk::Jwk {
            common,
            algorithm: jwk::AlgorithmParameters::OctetKeyPair(jwk::OctetKeyPairParameters {
                key_type: jwk::OctetKeyPairType::OctetKeyPair,
                curve: jwk::EllipticCurve::Ed25519,
                x: BASE64_URL_SAFE_NO_PAD.encode(key.as_bytes()),
            }),
        },
    };

    Ok(jwks)
}

fn decode_as_public_key_pem(pem_str: &str) -> Result<String> {
    Ok(match decode_as_public_key(pem_str)? {
        PublicKey::Rsa(rsa_public_key) => rsa::pkcs8::EncodePublicKey::to_public_key_pem(
            &rsa_public_key,
            rsa::pkcs8::LineEnding::LF,
        ),
        PublicKey::ECP256(public_key) => {
            p256::elliptic_curve::pkcs8::EncodePublicKey::to_public_key_pem(
                &public_key,
                p256::elliptic_curve::pkcs8::LineEnding::LF,
            )
        }
        PublicKey::ECP384(public_key) => {
            p384::elliptic_curve::pkcs8::EncodePublicKey::to_public_key_pem(
                &public_key,
                p384::elliptic_curve::pkcs8::LineEnding::LF,
            )
        }
        PublicKey::Ed25519(verifying_key) => {
            ed25519_dalek::pkcs8::EncodePublicKey::to_public_key_pem(
                &verifying_key,
                ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF,
            )
        }
    }?)
}

#[derive(Debug, Clone)]
pub enum KeyMaterial {
    JwksUrl {
        url: String,
    },
    PublicKey {
        pem: String,
    },
    Jwks {
        jwks_out: Option<PathBuf>,
        overwrite: bool,
        jwks: jwk::JwkSet,
    },
    PrivateKeyAndJwks {
        jwks_out: PathBuf,
        key_out: PathBuf,
        jwks_out_overwrite: bool,
        key_out_overwrite: bool,
        private: rsa::pkcs8::der::zeroize::Zeroizing<String>,
        jwks: jwk::JwkSet,
    },
}

impl WriteOutChecks for KeyMaterial {
    fn should_write(&self) -> bool {
        match self {
            KeyMaterial::JwksUrl { .. } => false,
            KeyMaterial::PublicKey { .. } => false,
            KeyMaterial::Jwks { jwks_out, .. } => jwks_out.is_some(),
            KeyMaterial::PrivateKeyAndJwks { .. } => true,
        }
    }

    fn can_write(&self) -> Result<()> {
        // private key write out
        {
            if let KeyMaterial::PrivateKeyAndJwks {
                key_out,
                key_out_overwrite: key_overwrite,
                ..
            } = self
            {
                can_write(key_out, *key_overwrite, "--key-out", "--key-out-overwrite")?;
            }
        }

        let (path, overwrite) = match self {
            KeyMaterial::JwksUrl { .. }
            | KeyMaterial::PublicKey { .. }
            | KeyMaterial::Jwks { jwks_out: None, .. } => {
                return Ok(());
            }
            KeyMaterial::Jwks {
                jwks_out: Some(jwks_out),
                overwrite,
                ..
            } => (jwks_out, overwrite),
            KeyMaterial::PrivateKeyAndJwks {
                jwks_out,
                jwks_out_overwrite: jwks_overwrite,
                ..
            } => (jwks_out, jwks_overwrite),
        };

        can_write(path, *overwrite, "--jwks-out", "--jwks-out-overwrite")?;

        Ok(())
    }
}

impl KeyMaterial {
    pub fn write_out(&self) -> Result<()> {
        // private key write out
        {
            if let KeyMaterial::PrivateKeyAndJwks {
                key_out,
                key_out_overwrite: key_overwrite,
                private,
                ..
            } = self
            {
                write_file(
                    key_out,
                    *key_overwrite,
                    private.as_bytes(),
                    "--key-out",
                    "--key-out-overwrite",
                )?;
            }
        }

        let (path, overwrite, content) = match self {
            KeyMaterial::JwksUrl { .. }
            | KeyMaterial::PublicKey { .. }
            | KeyMaterial::Jwks { jwks_out: None, .. } => {
                return Ok(());
            }
            KeyMaterial::Jwks {
                jwks_out: Some(jwks_out),
                overwrite,
                jwks,
            } => (jwks_out, overwrite, jwks),
            KeyMaterial::PrivateKeyAndJwks {
                jwks_out,
                jwks_out_overwrite: jwks_overwrite,
                jwks,
                ..
            } => (jwks_out, jwks_overwrite, jwks),
        };

        let content = serde_json::to_vec_pretty(&content).inspect_err(
            |error| error!(%error, path = %print_path(path), "failed to serialize jwks"),
        )?;
        write_file(
            path,
            *overwrite,
            content.as_slice(),
            "--jwks-out",
            "--jwks-out-overwrite",
        )?;

        Ok(())
    }
}

impl KeyPairManagement {
    pub fn to_pair(&self) -> Result<KeyMaterial> {
        match (
            &self.pem,
            &self.jwks_in,
            &self.jwks_from_pem,
            &self.jwks_url,
            &self.jwks_out.jwks_out,
        ) {
            (None, None, None, None, None) => {
                out!(
                    "one flag in --pem, --jwks, --jwks-from-pem, --jwks-url, --jwks-out must be set"
                );

                Err(Error::MissingArgument)
            }
            (Some(_), Some(_), ..)
            | (_, Some(_), Some(_), ..)
            | (Some(_), _, Some(_), ..)
            | (Some(_), _, _, Some(_), ..)
            | (_, Some(_), _, Some(_), ..)
            | (_, _, Some(_), Some(_), ..) => {
                out!("flags --pem, --jwks, --jwks-from-pem, and --jwks-url are mutually exclusive");

                Err(Error::TooManyArguments)
            }
            (Some(pem_path), None, None, None, jwks_out) => {
                if jwks_out.is_some() {
                    out!(
                        "flag --jwks-out and/or --jwks-out-overwrite are not allowed when input is a public key in pem format —  \
                         use \"--jwks-from-pem <path>\" and \"--jwks-out <path>\" to convert to jwks"
                    );
                    return Err(Error::TooManyArguments);
                }

                let input = fs::read_to_string(pem_path).inspect_err(
                    |error| error!(%error, path = %print_path(pem_path), "failed to read PEM file"),
                )?;

                Ok(KeyMaterial::PublicKey {
                    pem: decode_as_public_key_pem(&input)?,
                })
            }
            // => jwks
            (None, Some(jwks_path), None, None, jwks_out) => {
                if jwks_out.is_some() {
                    warn!("flag --jwks-out and/or --jwks-out-overwrite unused");
                }

                let jwks = fs::read(jwks_path).inspect_err(
                    |error| error!(%error, path = %print_path(jwks_path), "failed to read jwks"),
                )?;
                let jwks = serde_json::from_slice::<jwk::Jwk>(&jwks)
                    .map(|jwk| jwk::JwkSet { keys: vec![jwk] })
                    .or_else(|_| serde_json::from_slice::<jwk::JwkSet>(&jwks))
                    .inspect_err(|error| error!(%error, path = %print_path(jwks_path), "failed to parse input as jwks"))?;

                Ok(KeyMaterial::Jwks {
                    jwks_out: None,
                    overwrite: Default::default(),
                    jwks,
                })
            }
            // => conversion from pem to jwks
            (None, None, Some(pem_path), None, jwks_out) => {
                let jwks_out = match jwks_out {
                    None => {
                        out!("flag --jwks-from-pem requires at least --jwks-out");
                        return Err(Error::MissingArgument);
                    }
                    Some(x) => x,
                };
                let input = fs::read_to_string(pem_path).inspect_err(
                    |error| error!(%error, path = %print_path(pem_path), "failed to read PEM file"),
                )?;
                let mut pub_key = decode_as_public_key_jwks(&input)
                    .inspect_err(|error| error!(%error, "failed to decode public key form PEM"))?;
                let kid = match &self.kid {
                    None => pub_key.thumbprint(jwk::ThumbprintHash::SHA256),
                    Some(x) => x.to_string(),
                };
                let _ = pub_key.common.key_id.insert(kid);

                Ok(KeyMaterial::Jwks {
                    jwks_out: jwks_out.clone().into(),
                    overwrite: self.jwks_out.jwks_out_overwrite,
                    jwks: jwk::JwkSet {
                        keys: vec![pub_key],
                    },
                })
            }
            (None, None, None, None, Some(jwks_out)) => {
                let key_out = match &self.key_out.key_out {
                    None => {
                        out!("flag --jwks-out requires at least --key-out");
                        return Err(Error::MissingArgument);
                    }
                    Some(x) => x,
                };

                let bits = 2048;
                let private_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits)
                    .inspect_err(|error| error!(%error, "failed to generate RSA key pair"))?;
                let private_key_pem = rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(
                    &private_key,
                    rsa::pkcs8::LineEnding::LF,
                )
                .inspect_err(
                    |error| error!(%error, "failed to encode RSA private key to pkcs8 PEM"),
                )?;
                let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(
                    private_key_pem.as_bytes(),
                )
                .inspect_err(
                    |error| error!(%error, "failed to create encoding key from pkcs8 RSA PEM"),
                )?;
                let mut jwk =
                    jwk::Jwk::from_encoding_key(&encoding_key, jsonwebtoken::Algorithm::RS256)
                        .inspect_err(
                            |error| error!(%error, "failed to create jwks from pkcs8 RSA PEM"),
                        )?;

                let _ = jwk
                    .common
                    .public_key_use
                    .insert(jwk::PublicKeyUse::Signature);
                let _ = jwk
                    .common
                    .key_operations
                    .insert(vec![jwk::KeyOperations::Verify]);
                let _ = jwk.common.key_id.insert(
                    self.kid
                        .clone()
                        .unwrap_or_else(|| jwk.thumbprint(jwk::ThumbprintHash::SHA256)),
                );

                Ok(KeyMaterial::PrivateKeyAndJwks {
                    jwks_out: jwks_out.clone(),
                    jwks_out_overwrite: self.jwks_out.jwks_out_overwrite,
                    key_out: key_out.clone(),
                    key_out_overwrite: self.key_out.key_out_overwrite,
                    private: private_key_pem,
                    jwks: jwk::JwkSet { keys: vec![jwk] },
                })
            }
            (None, None, None, Some(url), jwks_out) => {
                if jwks_out.is_some() {
                    warn!("flag --jwks-out and/or --jwks-out-overwrite unused");
                }

                Ok(KeyMaterial::JwksUrl {
                    url: url.to_string(),
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct ClientSecret {
    pub secret: Sensitive,
    out: Option<PathBuf>,
    overwrite: bool,
}

impl WriteOutChecks for ClientSecret {
    fn should_write(&self) -> bool {
        self.out.is_some()
    }

    fn can_write(&self) -> Result<()> {
        if let Some(out) = &self.out {
            can_write(
                out,
                self.overwrite,
                "--secret-out",
                "--secret-out-overwrite",
            )?;
        }
        Ok(())
    }
}

impl ClientSecret {
    pub fn write_out(&self) -> Result<()> {
        if let Some(out) = &self.out {
            write_file(
                out,
                self.overwrite,
                self.secret.read().as_bytes(),
                "--secret-out",
                "--secret-out-overwrite",
            )?;
        }

        Ok(())
    }
}

#[derive(Parser, Default)]
pub struct ClientSecretManagement {
    /// Basic secret or HMAC secret for client-secret-jwt auth method
    #[arg(long = "secret")]
    secret: Option<PathBuf>,
    /// Secret for client when set by remote server
    #[arg(long = "secret-out")]
    secret_out: Option<PathBuf>,
    /// Secret for client when set by remote server
    #[arg(long = "secret-out-overwrite", default_value = "false")]
    secret_out_overwrite: bool,
}

fn generate_client_secret() -> String {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    use rand::{TryRng, rngs::SysRng};

    let mut bytes = vec![0u8; 32];
    SysRng.try_fill_bytes(&mut bytes).unwrap();
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

impl ClientSecretManagement {
    pub fn used(&self) -> Vec<&'static str> {
        let mut used = vec![];

        if self.secret.is_some() {
            used.push("--secret");
        }

        if self.secret_out.is_some() {
            used.push("--secret-out")
        }

        used
    }

    pub fn to_secret(&self) -> Result<ClientSecret> {
        match (&self.secret, &self.secret_out) {
            (None, None) => {
                out!("either --secret or --secret-out must be set");

                Err(Error::MissingArgument)
            }
            (None, Some(out)) => Ok(ClientSecret {
                secret: generate_client_secret().into(),
                out: Some(out.clone()),
                overwrite: self.secret_out_overwrite,
            }),
            (Some(secret_path), out) => {
                let input = fs::read_to_string(secret_path).inspect_err(
                    |error| error!(%error, path = %print_path(secret_path), "failed to read file"),
                )?;

                Ok(ClientSecret {
                    secret: input.into(),
                    out: out.clone(),
                    overwrite: self.secret_out_overwrite,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum TokenAuthMethod {
    #[value(name = "client_secret_basic")]
    ClientSecretBasic,
    #[value(name = "client_secret_post")]
    ClientSecretPost,
    #[value(name = "client_secret_jwt")]
    ClientSecretJWT,
    #[value(name = "private_key_jwt")]
    PrivateKeyJWT,
    #[value(name = "tls_client_auth")]
    TlsClientAuth,
}

impl fmt::Display for TokenAuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TokenAuthMethod::ClientSecretBasic => oauth2::CLIENT_SECRET_BASIC,
                TokenAuthMethod::ClientSecretPost => oauth2::CLIENT_SECRET_POST,
                TokenAuthMethod::ClientSecretJWT => oauth2::CLIENT_SECRET_JWT,
                TokenAuthMethod::PrivateKeyJWT => oauth2::PRIVATE_KEY_JWT,
                TokenAuthMethod::TlsClientAuth => oauth2::TLS_CLIENT_AUTH,
            }
        )
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum JsonPatchMode {
    #[default]
    #[value(name = "merge")]
    Merge,
    #[value(name = "replace")]
    Replace,
    /// Used on a field named `attributes`
    #[value(name = "replace-attributes-only")]
    ReplaceAttributesOnly,
}

pub struct Json {
    content: serde_json::Value,
    patch_mode: JsonPatchMode,
}

impl Json {
    pub fn used(&self) -> bool {
        !matches!(self.content, serde_json::Value::Null)
    }

    pub fn mode(&self) -> JsonPatchMode {
        self.patch_mode
    }

    pub fn parse_from_json_value<T>(&self) -> Result<T>
    where
        for<'de> T: serde::Deserialize<'de>,
    {
        Ok(serde_json::from_value(self.content.clone())?)
    }
}

#[derive(Parser, Default)]
pub struct JsonManagement {
    /// Extra parameters to include in the client representation
    /// in JSON format
    #[arg(long = "json")]
    json: Option<String>,
    /// Extra parameters to include in the client representation
    /// in JSON format - unused when `--json` is set inline
    #[arg(long = "json-in")]
    json_in: Option<PathBuf>,
    /// When representation is valued, sets the mode of patching
    /// with other flags and defaults
    #[arg(long = "patch-mode", value_enum)]
    patch_mode: Option<JsonPatchMode>,
}

impl JsonManagement {
    pub fn parse_into_json(&self) -> Result<Json> {
        let content = match (self.json.as_deref(), self.json_in.as_deref()) {
            (Some(content), path) => {
                if path.is_some() {
                    warn!("flag --json-in unused");
                }
                serde_json::to_value(content).inspect_err(|error| {
                    error!(%error, "failed to deserialize json");
                })?
            }
            (None, Some(path)) => {
                // read
                let input = fs::read_to_string(path).inspect_err(
                    |error| error!(%error, path = %print_path(path), "failed to read file"),
                )?;
                serde_json::to_value(&input).inspect_err(|error| {
                    error!(%error, "failed to deserialize json");
                })?
            }
            (None, None) => serde_json::Value::Null,
        };

        Ok(Json {
            content,
            patch_mode: self.patch_mode.unwrap_or_default(),
        })
    }
}

#[derive(Parser, Default)]
pub struct Password {
    out: PathBuf,
    overwrite: bool,
}

impl WriteOutChecks for Password {
    fn should_write(&self) -> bool {
        true
    }

    fn can_write(&self) -> Result<()> {
        can_write(
            &self.out,
            self.overwrite,
            "--password-out",
            "--password-out-overwrite",
        )?;

        Ok(())
    }
}

impl Password {
    pub fn write_out<T>(&self, content: T) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        write_file(
            &self.out,
            self.overwrite,
            content.as_ref(),
            "--password-out",
            "--password-out-overwrite",
        )?;

        Ok(())
    }
}

#[derive(Parser, Default)]
pub struct PasswordManagement {
    /// Password for user
    #[arg(long = "password-out")]
    password_out: Option<PathBuf>,
    /// Overwrite existing user password file
    #[arg(long = "password-out-overwrite", default_value = "false")]
    password_out_overwrite: bool,
}

impl PasswordManagement {
    #[allow(unused)]
    pub fn used(&self) -> Vec<&'static str> {
        let mut used = vec![];

        if self.password_out.is_some() {
            used.push("--password-out");
        }

        used
    }

    pub fn to_password(&self) -> Result<Password> {
        match &self.password_out {
            None => {
                out!("argument --password-out must be set");

                Err(Error::MissingArgument)
            }
            Some(out) => Ok(Password {
                out: out.clone(),
                overwrite: self.password_out_overwrite,
            }),
        }
    }
}

#[derive(Subcommand, Completions)]
pub enum Commands {
    /// Manage CLI contexts
    #[command(name = "bootstrap")]
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommands,
        /// Working realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
    },
    /// Manage CLI contexts
    #[command(name = "context", alias = "ctx")]
    Context {
        #[command(subcommand)]
        command: ContextCommands,
    },
    /// Manage CLI contexts
    #[command(name = "authorize", alias = "auth")]
    Authorize {
        #[command(subcommand)]
        command: AuthorizeCommands,
    },
    /// Manage realm clients
    #[command(name = "clients", alias = "c")]
    Clients {
        #[command(subcommand)]
        command: ClientsCommands,
        /// Working realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
    },
    /// Manage realm users
    #[command(name = "users", alias = "u")]
    Users {
        #[command(subcommand)]
        command: UsersCommands,
        /// Working realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
    },
    /// Manage realms
    #[command(name = "realms", alias = "r")]
    Realms {
        #[command(subcommand)]
        command: RealmsCommands,
    },

    /// Hidden completion command
    #[command(name = "completions", hide = true)]
    Completions {
        #[command(subcommand)]
        command: CompletionsCommands,
    },
}

#[derive(Parser)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}
