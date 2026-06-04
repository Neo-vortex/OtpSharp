using FluentAssertions;
using OtpSharp.Core;
using OtpSharp.Steam;
using Xunit;

namespace OtpSharp.Tests;

public class SteamGuardTests
{
    [Fact]
    public void Generate_Returns5CharCode()
    {
        using var secret = OtpSecret.Generate(20);
        var steam = new SteamGuardGenerator(secret);

        SteamGuardCode code = steam.Generate();

        code.Code.Should().HaveLength(5);
        code.Code.Should().MatchRegex(@"^[23456789BCDFGHJKMNPQRTVWXY]{5}$");
    }

    [Fact]
    public void Validate_AcceptsCurrentCode()
    {
        using var secret = OtpSecret.Generate(20);
        var steam = new SteamGuardGenerator(secret);

        string code = steam.Generate().Code;
        var result = steam.Validate(code);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Validate_AcceptsCodeCaseInsensitive()
    {
        using var secret = OtpSecret.Generate(20);
        var steam = new SteamGuardGenerator(secret);

        string code = steam.Generate().Code;
        var result = steam.Validate(code.ToLowerInvariant());

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Generate_FixedTime_IsDeterministic()
    {
        using var secret = OtpSecret.Generate(20);
        var time = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));

        var steam1 = new SteamGuardGenerator(secret, time);
        var steam2 = new SteamGuardGenerator(secret, time);

        steam1.Generate().Code.Should().Be(steam2.Generate().Code);
    }

    [Fact]
    public void RemainingSeconds_InRange()
    {
        using var secret = OtpSecret.Generate();
        var steam = new SteamGuardGenerator(secret);

        steam.RemainingSeconds().Should().BeInRange(1, 30);
    }

    [Fact]
    public void UsesOnlySteamAlphabetCharacters()
    {
        using var secret = OtpSecret.Generate();
        var steam = new SteamGuardGenerator(secret);

        for (int i = 0; i < 100; i++)
        {
            var time = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(i * 30));
            var gen  = new SteamGuardGenerator(secret, time);
            string code = gen.Generate().Code;

            foreach (char c in code)
                SteamGuardGenerator.SteamAlphabet.Should().Contain(c.ToString(),
                    $"character '{c}' in code '{code}' is not in Steam alphabet");
        }
    }
}
