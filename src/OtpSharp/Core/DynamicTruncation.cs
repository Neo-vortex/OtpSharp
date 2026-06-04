using System.Runtime.CompilerServices;

namespace OtpSharp.Core;

/// <summary>
/// Implements RFC 4226 §5.3 Dynamic Truncation and digit extraction.
/// </summary>
internal static class DynamicTruncation
{
    // Precomputed powers of 10 for digit modulus (up to 10 digits)
    private static readonly uint[] PowersOf10 =
    [
        1,          // 0
        10,         // 1
        100,        // 2
        1_000,      // 3
        10_000,     // 4
        100_000,    // 5
        1_000_000,  // 6
        10_000_000, // 7
        100_000_000,// 8
        1_000_000_000, // 9 (fits in uint)
    ];

    /// <summary>
    /// Extracts a numeric OTP code from an HMAC hash using RFC 4226 dynamic truncation.
    /// </summary>
    /// <param name="hash">The HMAC output (any length ≥ 20).</param>
    /// <param name="digits">Number of OTP digits (1–10).</param>
    /// <returns>The raw numeric code (unpadded).</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static uint Extract(ReadOnlySpan<byte> hash, int digits)
    {
        // Step 1: dynamic offset — low nibble of last byte
        int offset = hash[^1] & 0x0F;

        // Step 2: extract 4 bytes, mask top bit (always positive)
        uint p = ((uint)hash[offset]     & 0x7F) << 24
               | ((uint)hash[offset + 1] & 0xFF) << 16
               | ((uint)hash[offset + 2] & 0xFF) <<  8
               | ((uint)hash[offset + 3] & 0xFF);

        // Step 3: modulo by 10^digits
        return digits < PowersOf10.Length
            ? p % PowersOf10[digits]
            : p % (uint)Math.Pow(10, digits);
    }

    /// <summary>
    /// Formats a raw OTP code to a zero-padded string of the specified digit count.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static string Format(uint code, int digits)
        => code.ToString().PadLeft(digits, '0');

    /// <summary>
    /// Performs constant-time string comparison to prevent timing attacks.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static bool ConstantTimeEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;

        int result = 0;
        for (int i = 0; i < a.Length; i++)
            result |= a[i] ^ b[i];

        return result == 0;
    }
}
