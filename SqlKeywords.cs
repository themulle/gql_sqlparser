namespace TrinoSqlEngine;

using System.Text.RegularExpressions;

public static class SqlKeywords
{
    private static readonly Regex KeywordLiteralRegex = new(@"^'[A-Z_]+'$", RegexOptions.Compiled);

    public static bool IsKeyword(int tokenType)
    {
        if (tokenType < 0) return false;
        string? name = SqlBaseLexer.DefaultVocabulary.GetLiteralName(tokenType);
        return name != null && KeywordLiteralRegex.IsMatch(name);
    }
}
