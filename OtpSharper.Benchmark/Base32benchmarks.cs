using BenchmarkDotNet.Attributes;
using OtpNet;
using OtpSharper.Core;

namespace OtpSharp.Benchmarks;

/// <summary>
/// Benchmarks Base32 encoding and decoding.
/// Base32 is called on every secret setup and otpauth:// URI parse.
/// </summary>
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
public class Base32Benchmarks
{
    // Various secret sizes that appear in the wild
    private static readonly byte[] Bytes20 = new byte[20];    // SHA1 key  (160 bits)
    private static readonly byte[] Bytes32 = new byte[32];    // SHA256 key (256 bits)
    private static readonly byte[] Bytes64 = new byte[64];    // SHA512 key (512 bits)

    private static readonly string Base32_20 = Base32Encoding.ToString(Bytes20);
    private static readonly string Base32_32 = Base32Encoding.ToString(Bytes32);
    private static readonly string Base32_64 = Base32Encoding.ToString(Bytes64);

    static Base32Benchmarks()
    {
        // Fill with deterministic non-zero bytes
        for (int i = 0; i < 20; i++) Bytes20[i] = (byte)(i + 1);
        for (int i = 0; i < 32; i++) Bytes32[i] = (byte)(i + 1);
        for (int i = 0; i < 64; i++) Bytes64[i] = (byte)(i + 1);
    }

    // ── Encode: 20-byte secret (SHA1 standard) ────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("Base32_Encode_20bytes")]
    public string TheirEncode20() => Base32Encoding.ToString(Bytes20);

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("Base32_Encode_20bytes")]
    public string OurEncode20() => OtpSharper.Core.Base32.Encode(Bytes20, padOutput: false);

    // ── Encode: 32-byte secret (SHA256) ──────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("Base32_Encode_32bytes")]
    public string TheirEncode32() => Base32Encoding.ToString(Bytes32);

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("Base32_Encode_32bytes")]
    public string OurEncode32() => OtpSharper.Core.Base32.Encode(Bytes32, padOutput: false);

    // ── Encode: 64-byte secret (SHA512) ──────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("Base32_Encode_64bytes")]
    public string TheirEncode64() => Base32Encoding.ToString(Bytes64);

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("Base32_Encode_64bytes")]
    public string OurEncode64() => OtpSharper.Core.Base32.Encode(Bytes64, padOutput: false);

    // ── Decode: 20-byte secret ────────────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("Base32_Decode_20bytes")]
    public byte[] TheirDecode20() => Base32Encoding.ToBytes(Base32_20);

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("Base32_Decode_20bytes")]
    public byte[] OurDecode20() => OtpSharper.Core.Base32.Decode(Base32_20);

    // ── Decode: 32-byte secret ────────────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("Base32_Decode_32bytes")]
    public byte[] TheirDecode32() => Base32Encoding.ToBytes(Base32_32);

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("Base32_Decode_32bytes")]
    public byte[] OurDecode32() => OtpSharper.Core.Base32.Decode(Base32_32);

    // ── Decode: 64-byte secret ────────────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("Base32_Decode_64bytes")]
    public byte[] TheirDecode64() => Base32Encoding.ToBytes(Base32_64);

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("Base32_Decode_64bytes")]
    public byte[] OurDecode64() => OtpSharper.Core.Base32.Decode(Base32_64);
}
