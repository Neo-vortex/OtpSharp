using OtpSharper.Core;
using OtpSharper.Totp;

namespace OtpSharper.Abstractions;

/// <summary>
/// Stateless TOTP validation service, suitable for dependency injection.
/// </summary>
/// <remarks>
/// Unlike <see cref="TotpGenerator"/> (which is bound to a single secret),
/// this service accepts the secret per-call, making it suitable for multi-user
/// systems where each user has their own secret stored externally.
/// </remarks>
public sealed class TotpValidationService
{
    private readonly TotpOptions _options;

    /// <summary>Creates a validation service with the given options.</summary>
    public TotpValidationService(TotpOptions? options = null)
        => _options = options ?? TotpOptions.Default;

    /// <summary>Creates a validation service using the fluent builder.</summary>
    public TotpValidationService(Action<TotpOptionsBuilder> configure)
    {
        var b = new TotpOptionsBuilder();
        configure(b);
        _options = b.Build();
    }

    // ── Validation ────────────────────────────────────────────────────────────

    /// <summary>
    /// Validates a TOTP code against a Base32-encoded secret.
    /// </summary>
    public OtpValidationResult Validate(string base32Secret, string userCode)
    {
        using var secret = OtpSecret.FromBase32(base32Secret);
        return new TotpGenerator(secret, _options).Validate(userCode);
    }

    /// <summary>
    /// Validates a TOTP code against a raw secret byte array.
    /// </summary>
    public OtpValidationResult Validate(byte[] secretBytes, string userCode)
    {
        using var secret = new OtpSecret(secretBytes);
        return new TotpGenerator(secret, _options).Validate(userCode);
    }

    /// <summary>
    /// Validates a TOTP code against an <see cref="OtpSecret"/>.
    /// </summary>
    public OtpValidationResult Validate(OtpSecret secret, string userCode)
        => new TotpGenerator(secret, _options).Validate(userCode);

    // ── Generation helpers ────────────────────────────────────────────────────

    /// <summary>
    /// Generates the current TOTP code for a Base32-encoded secret.
    /// Useful for admin tools and verification flows.
    /// </summary>
    public OtpCode Generate(string base32Secret)
    {
        using var secret = OtpSecret.FromBase32(base32Secret);
        return new TotpGenerator(secret, _options).Generate();
    }

    /// <summary>
    /// Generates the current TOTP code for a raw secret.
    /// </summary>
    public OtpCode Generate(byte[] secretBytes)
    {
        using var secret = new OtpSecret(secretBytes);
        return new TotpGenerator(secret, _options).Generate();
    }

    /// <summary>Active options used by this service.</summary>
    public TotpOptions Options => _options;
}
