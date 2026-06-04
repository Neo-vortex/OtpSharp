using OtpSharper.Algorithms;

namespace OtpSharper.Hotp;

/// <summary>
/// Configuration for an HOTP generator/validator.
/// </summary>
public sealed class HotpOptions
{
    /// <summary>RFC 4226 default: HMAC-SHA1.</summary>
    public const OtpAlgorithm DefaultAlgorithm = OtpAlgorithm.HmacSha1;

    /// <summary>RFC 4226 default: 6 digits.</summary>
    public const int DefaultDigits = 6;

    /// <summary>
    /// HMAC algorithm. Default: HMAC-SHA1 (RFC 4226 §5.1).
    /// </summary>
    public OtpAlgorithm Algorithm { get; init; } = DefaultAlgorithm;

    /// <summary>
    /// OTP digit count. Range: 1–10. Default: 6.
    /// </summary>
    public int Digits { get; init; } = DefaultDigits;

    /// <summary>
    /// How many consecutive counter values to check ahead during validation.
    /// Handles counter desynchronisation. RFC 4226 §7.4 recommends ≤ 10.
    /// Default: 5.
    /// </summary>
    public int LookAheadWindow { get; init; } = 5;

    /// <summary>Validates option values.</summary>
    public void Validate()
    {
        if (Digits is < 1 or > 10)
            throw new InvalidOperationException($"{nameof(Digits)} must be 1–10.");
        if (LookAheadWindow < 0)
            throw new InvalidOperationException($"{nameof(LookAheadWindow)} must be ≥ 0.");
    }

    /// <summary>RFC 4226 defaults: SHA1, 6 digits, 5-step look-ahead.</summary>
    public static HotpOptions Default => new();
}
