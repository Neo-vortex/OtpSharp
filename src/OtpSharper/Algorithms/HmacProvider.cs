using System.Security.Cryptography;

namespace OtpSharper.Algorithms;

/// <summary>
/// Factory and utilities for HMAC algorithm instances.
/// </summary>
internal static class HmacProvider
{
    /// <summary>
    /// Creates an <see cref="HMAC"/> instance for the given algorithm and key.
    /// </summary>
    /// <param name="algorithm">The algorithm to use.</param>
    /// <param name="key">The secret key bytes.</param>
    /// <returns>An initialized <see cref="HMAC"/> instance. Caller must dispose.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Unknown algorithm.</exception>
    internal static HMAC Create(OtpAlgorithm algorithm, byte[] key) => algorithm switch
    {
        OtpAlgorithm.HmacSha1    => new HMACSHA1(key),
        OtpAlgorithm.HmacSha256  => new HMACSHA256(key),
        OtpAlgorithm.HmacSha384  => new HMACSHA384(key),
        OtpAlgorithm.HmacSha512  => new HMACSHA512(key),
        OtpAlgorithm.HmacSha3_256 => new HMACSHA3_256(key),
        OtpAlgorithm.HmacSha3_512 => new HMACSHA3_512(key),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported OTP algorithm.")
    };

    /// <summary>
    /// Computes the HMAC hash for a given counter value using the specified algorithm and key.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <param name="key">The raw secret key.</param>
    /// <param name="counter">The 8-byte big-endian counter value.</param>
    /// <returns>The HMAC hash bytes.</returns>
    internal static byte[] ComputeHash(OtpAlgorithm algorithm, byte[] key, long counter)
    {
        Span<byte> counterBytes = stackalloc byte[8];
        WriteBigEndian(counterBytes, counter);

        using HMAC hmac = Create(algorithm, key);
        return hmac.ComputeHash(counterBytes.ToArray());
    }

    /// <summary>
    /// Returns the name string used in otpauth:// URIs.
    /// </summary>
    internal static string ToUriString(OtpAlgorithm algorithm) => algorithm switch
    {
        OtpAlgorithm.HmacSha1     => "SHA1",
        OtpAlgorithm.HmacSha256   => "SHA256",
        OtpAlgorithm.HmacSha384   => "SHA384",
        OtpAlgorithm.HmacSha512   => "SHA512",
        OtpAlgorithm.HmacSha3_256 => "SHA3-256",
        OtpAlgorithm.HmacSha3_512 => "SHA3-512",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };

    /// <summary>
    /// Parses algorithm name from otpauth:// URI string.
    /// </summary>
    internal static OtpAlgorithm FromUriString(string? value) => value?.ToUpperInvariant() switch
    {
        null or "" or "SHA1" => OtpAlgorithm.HmacSha1,
        "SHA256"             => OtpAlgorithm.HmacSha256,
        "SHA384"             => OtpAlgorithm.HmacSha384,
        "SHA512"             => OtpAlgorithm.HmacSha512,
        "SHA3-256"           => OtpAlgorithm.HmacSha3_256,
        "SHA3-512"           => OtpAlgorithm.HmacSha3_512,
        _                    => throw new ArgumentException($"Unknown algorithm: '{value}'", nameof(value))
    };

    private static void WriteBigEndian(Span<byte> buffer, long value)
    {
        buffer[0] = (byte)((value >> 56) & 0xFF);
        buffer[1] = (byte)((value >> 48) & 0xFF);
        buffer[2] = (byte)((value >> 40) & 0xFF);
        buffer[3] = (byte)((value >> 32) & 0xFF);
        buffer[4] = (byte)((value >> 24) & 0xFF);
        buffer[5] = (byte)((value >> 16) & 0xFF);
        buffer[6] = (byte)((value >>  8) & 0xFF);
        buffer[7] = (byte)( value        & 0xFF);
    }
}
