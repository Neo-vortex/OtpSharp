using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace OtpSharp.Core;

/// <summary>
/// Represents an OTP secret key with support for multiple encodings.
/// The raw bytes are kept in a pinned, zeroed-on-dispose buffer for security hygiene.
/// </summary>
public sealed class OtpSecret : IDisposable
{
    private byte[]? _bytes;
    private bool _disposed;
    private GCHandle _pin;

    // ── Constructors ──────────────────────────────────────────────────────────

    /// <summary>Wraps raw secret bytes. A copy is made and pinned.</summary>
    public OtpSecret(ReadOnlySpan<byte> rawBytes)
    {
        if (rawBytes.IsEmpty)
            throw new ArgumentException("Secret must not be empty.", nameof(rawBytes));

        _bytes = GC.AllocateArray<byte>(rawBytes.Length, pinned: true);
        rawBytes.CopyTo(_bytes);
        _pin = GCHandle.Alloc(_bytes, GCHandleType.Pinned);
    }

    /// <summary>Decodes a Base32-encoded secret string.</summary>
    /// <exception cref="FormatException">Invalid Base32 encoding.</exception>
    public static OtpSecret FromBase32(string base32)
        => new(Base32.Decode(base32));

    /// <summary>Decodes a Base64-encoded secret string.</summary>
    public static OtpSecret FromBase64(string base64)
        => new(Convert.FromBase64String(base64));

    /// <summary>Uses the UTF-8 bytes of a plain-text string as the secret (not recommended for production).</summary>
    public static OtpSecret FromUtf8String(string plainText)
        => new(Encoding.UTF8.GetBytes(plainText));

    /// <summary>Generates a new cryptographically random secret of the specified byte length.</summary>
    /// <param name="byteLength">Default 20 for SHA1, 32 for SHA256, 64 for SHA512.</param>
    public static OtpSecret Generate(int byteLength = 20)
    {
        byte[] bytes = new byte[byteLength];
        RandomNumberGenerator.Fill(bytes);
        var secret = new OtpSecret(bytes);
        CryptographicOperations.ZeroMemory(bytes);
        return secret;
    }

    // ── Access ────────────────────────────────────────────────────────────────

    /// <summary>Number of bytes in the secret.</summary>
    public int Length => EnsureAlive().Length;

    /// <summary>Returns a copy of the raw secret bytes.</summary>
    public byte[] ToByteArray()
    {
        byte[] src = EnsureAlive();
        byte[] copy = new byte[src.Length];
        src.CopyTo(copy, 0);
        return copy;
    }

    /// <summary>Returns the secret encoded as a Base32 string (no padding).</summary>
    public string ToBase32(bool padOutput = false)
        => Base32.Encode(EnsureAlive(), padOutput);

    /// <summary>Returns the secret encoded as a Base64 string.</summary>
    public string ToBase64()
        => Convert.ToBase64String(EnsureAlive());

    /// <summary>Provides read-only span access to the raw bytes. Valid only while this instance is alive.</summary>
    internal ReadOnlySpan<byte> Span => EnsureAlive().AsSpan();

    // ── Disposal ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Zeroes and releases the pinned key memory.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_bytes is not null)
        {
            CryptographicOperations.ZeroMemory(_bytes);
            _bytes = null;
        }

        if (_pin.IsAllocated)
            _pin.Free();
    }

    private byte[] EnsureAlive()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _bytes!;
    }
}
