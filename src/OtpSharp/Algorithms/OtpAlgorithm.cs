namespace OtpSharp.Algorithms;

/// <summary>
/// Specifies the HMAC algorithm used for OTP computation.
/// </summary>
/// <remarks>
/// RFC 4226 mandates HMAC-SHA1. RFC 6238 extends this to allow SHA-256 and SHA-512.
/// SHA-3 variants are provided as an extension beyond the RFC for future-proofing.
/// Note: most authenticator apps (Google Authenticator, Authy) only support SHA1.
/// </remarks>
public enum OtpAlgorithm
{
    /// <summary>HMAC-SHA1 — RFC 4226/6238 standard. Universally supported.</summary>
    HmacSha1 = 0,

    /// <summary>HMAC-SHA256 — RFC 6238 optional variant. Better security.</summary>
    HmacSha256 = 1,

    /// <summary>HMAC-SHA384 — Extended variant. Wider HMAC output.</summary>
    HmacSha384 = 2,

    /// <summary>HMAC-SHA512 — RFC 6238 optional variant. Maximum HMAC security.</summary>
    HmacSha512 = 3,

    /// <summary>HMAC-SHA3-256 — Keccak-based, post-quantum resistant candidate.</summary>
    HmacSha3_256 = 4,

    /// <summary>HMAC-SHA3-512 — Keccak-based, post-quantum resistant candidate.</summary>
    HmacSha3_512 = 5,
}
