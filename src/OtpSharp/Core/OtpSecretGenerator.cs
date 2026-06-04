using System.Security.Cryptography;

namespace OtpSharp.Core;

/// <summary>
/// Utilities for generating and evaluating OTP secret keys.
/// </summary>
public static class OtpSecretGenerator
{
    // ── Generation ────────────────────────────────────────────────────────────

    /// <summary>
    /// Generates a cryptographically random secret of the recommended byte length
    /// for the given HMAC algorithm.
    /// </summary>
    /// <param name="algorithm">The algorithm to generate a secret for.</param>
    /// <returns>A new <see cref="OtpSecret"/> of optimal length.</returns>
    public static OtpSecret GenerateForAlgorithm(OtpSharp.Algorithms.OtpAlgorithm algorithm)
    {
        int byteLength = RecommendedSecretBytes(algorithm);
        return OtpSecret.Generate(byteLength);
    }

    /// <summary>
    /// Returns the recommended secret byte length for the given algorithm.
    /// RFC 4226 §4 states the secret SHOULD be the same length as the HMAC output.
    /// </summary>
    public static int RecommendedSecretBytes(OtpSharp.Algorithms.OtpAlgorithm algorithm) => algorithm switch
    {
        OtpSharp.Algorithms.OtpAlgorithm.HmacSha1     => 20,  // 160-bit output
        OtpSharp.Algorithms.OtpAlgorithm.HmacSha256   => 32,  // 256-bit output
        OtpSharp.Algorithms.OtpAlgorithm.HmacSha384   => 48,  // 384-bit output
        OtpSharp.Algorithms.OtpAlgorithm.HmacSha512   => 64,  // 512-bit output
        OtpSharp.Algorithms.OtpAlgorithm.HmacSha3_256 => 32,
        OtpSharp.Algorithms.OtpAlgorithm.HmacSha3_512 => 64,
        _                                              => 32,
    };

    // ── Entropy evaluation ────────────────────────────────────────────────────

    /// <summary>
    /// Estimates the entropy of a Base32-encoded secret in bits.
    /// </summary>
    /// <param name="base32Secret">The Base32 secret string.</param>
    /// <returns>Entropy in bits, or 0 if the secret is invalid.</returns>
    public static double EstimateEntropyBits(string base32Secret)
    {
        if (!Base32.TryDecode(base32Secret, out byte[] bytes) || bytes.Length == 0)
            return 0;

        return bytes.Length * 8.0;
    }

    /// <summary>
    /// Assesses the strength of a secret.
    /// </summary>
    public static SecretStrength AssessStrength(string base32Secret)
    {
        double bits = EstimateEntropyBits(base32Secret);
        return bits switch
        {
            <= 80  => SecretStrength.Weak,      // ≤ 80 bits (≤ 10 bytes)
            < 128  => SecretStrength.Adequate,  // 81–127 bits
            < 256  => SecretStrength.Strong,    // 128–255 bits
            _      => SecretStrength.VeryStrong, // 256+ bits
        };
    }

    /// <summary>
    /// Verifies that a secret meets minimum security requirements.
    /// </summary>
    /// <param name="base32Secret">The Base32 secret to check.</param>
    /// <param name="minimumBits">Minimum required entropy bits. Default: 128.</param>
    /// <exception cref="CryptographicException">If the secret is too weak.</exception>
    public static void EnsureMinimumStrength(string base32Secret, int minimumBits = 128)
    {
        double bits = EstimateEntropyBits(base32Secret);
        if (bits < minimumBits)
            throw new CryptographicException(
                $"Secret has only ~{bits:F0} bits of entropy; minimum required is {minimumBits} bits. " +
                $"Generate a new secret with OtpSecret.Generate({(int)Math.Ceiling(minimumBits / 8.0)}).");
    }
}

/// <summary>Categorises the strength of an OTP secret.</summary>
public enum SecretStrength
{
    /// <summary>Below 80 bits — not acceptable for production.</summary>
    Weak,
    /// <summary>80–127 bits — acceptable but not recommended for new systems.</summary>
    Adequate,
    /// <summary>128–255 bits — recommended for most applications.</summary>
    Strong,
    /// <summary>256+ bits — maximum security, future-proof.</summary>
    VeryStrong,
}
