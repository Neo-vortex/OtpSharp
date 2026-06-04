using BenchmarkDotNet.Attributes;
using OtpNet;
using OtpSharp.Core;
using OtpSharp.Totp;
using OtpSharp.Uri;
using OtpUri = OtpSharp.Uri.OtpUri;

namespace OtpSharp.Benchmarks;

/// <summary>
/// Benchmarks otpauth:// URI building and parsing.
/// URI generation is called during user enrollment; parsing during QR scan import.
/// </summary>
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
public class OtpUriBenchmarks
{
    private static readonly byte[] SecretBytes = "12345678901234567890"u8.ToArray();
    private static readonly string SecretBase32 = OtpSharp.Core.Base32.Encode(SecretBytes, padOutput: false);
    private const string Label  = "alice@example.com";
    private const string Issuer = "ExampleApp";

    // Pre-built URI for parse benchmarks
    private static readonly string PrebuiltUri =
        $"otpauth://totp/{Issuer}:{Label}?secret={SecretBase32}&issuer={Issuer}&algorithm=SHA1&digits=6&period=30";

    // OtpSharp
    private OtpSecret _ourSecret = null!;
    private OtpUri    _ourUri    = null!;

    [GlobalSetup]
    public void Setup()
    {
        _ourSecret = new OtpSecret(SecretBytes);
        _ourUri    = OtpUri.ForTotp(Label, _ourSecret, TotpOptions.Default, Issuer);
    }

    [GlobalCleanup]
    public void Cleanup() => _ourSecret.Dispose();

    // ── Parse URI ─────────────────────────────────────────────────────────────
    // Note: Otp.NET does not have a URI parser; OtpSharp uniquely provides this.

    [Benchmark(Description = "OtpSharp")]
    [BenchmarkCategory("OtpUri_Parse")]
    public OtpUri OurUriParse()
        => OtpUri.Parse(PrebuiltUri);

    // ── Full round-trip (build then parse) ────────────────────────────────────

    [Benchmark(Description = "OtpSharp")]
    [BenchmarkCategory("OtpUri_RoundTrip")]
    public string OurUriRoundTrip()
    {
        string uri = _ourUri.ToUriString();
        var parsed = OtpUri.Parse(uri);
        return parsed.Secret;
    }
}
