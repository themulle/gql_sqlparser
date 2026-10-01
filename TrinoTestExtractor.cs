namespace TrinoSqlEngine;

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

public static class TrinoTestExtractor
{
    private static readonly Regex StatementCallRegex = new(
        "\\b(?:assertStatement|statement)\\s*\\(\\s*(?<content>\"\"\"[\\s\\S]*?\"\"\"|(?:\"(?:[^\"\\\\]|\\\\.)*\"[\\s\\+]*)+)",
        RegexOptions.Compiled);

    private static readonly Regex ExpressionCallRegex = new(
        "\\b(?:assertExpression|expression)\\s*\\(\\s*(?<content>\"\"\"[\\s\\S]*?\"\"\"|(?:\"(?:[^\"\\\\]|\\\\.)*\"[\\s\\+]*)+)",
        RegexOptions.Compiled);

    private static readonly Regex StatementFailsCallRegex = new(
        "(?:\\bassertStatementFails|\\bassertStatementIsInvalid)\\s*\\(\\s*(?<content>\"\"\"[\\s\\S]*?\"\"\"|(?:\"(?:[^\"\\\\]|\\\\.)*\"[\\s\\+]*)+)",
        RegexOptions.Compiled);

    private static readonly Regex ExpressionFailsCallRegex = new(
        "(?:\\bassertInvalidExpression|\\bassertExpressionIsInvalid|SQL_PARSER\\.createExpression)\\s*\\(\\s*(?<content>\"\"\"[\\s\\S]*?\"\"\"|(?:\"(?:[^\"\\\\]|\\\\.)*\"[\\s\\+]*)+)",
        RegexOptions.Compiled);

    private static readonly Regex StringChunkRegex = new(
        "\"\"\"(?<chunk>[\\s\\S]*?)\"\"\"|\"(?<chunk>(?:[^\"\\\\]|\\\\.)*)\"",
        RegexOptions.Compiled);

    public static List<string> ExtractQueries(string javaSource, Regex callRegex)
    {
        var matches = callRegex.Matches(javaSource);
        var queries = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (Match match in matches)
        {
            string content = match.Groups["content"].Value;
            var chunkMatches = StringChunkRegex.Matches(content);
            if (chunkMatches.Count == 0) continue;

            string fullQuery = "";
            foreach (Match chunkMatch in chunkMatches)
            {
                string chunk = chunkMatch.Groups["chunk"].Value;
                fullQuery += UnescapeJavaString(chunk);
            }

            fullQuery = fullQuery
                .Replace("%s", "t") // Handle Java template strings formatted with table names
                .Replace("\r\n", " ")
                .Replace("\n", " ")
                .Trim();

            if (!string.IsNullOrWhiteSpace(fullQuery) && seen.Add(fullQuery))
            {
                queries.Add(fullQuery);
            }
        }

        return queries;
    }

    public static void Extract(string javaFilePath, string outputJsonPath)
    {
        if (!File.Exists(javaFilePath))
        {
            Console.WriteLine($"File not found: {javaFilePath}");
            return;
        }

        string javaSource = File.ReadAllText(javaFilePath);
        var queries = ExtractQueries(javaSource, StatementCallRegex);

        SaveJson(queries, outputJsonPath);
        Console.WriteLine($"Extrahierte Queries: {queries.Count} -> {outputJsonPath}");
    }

    public static void ExtractAll(string javaFilePath, string fixturesDir)
    {
        if (!File.Exists(javaFilePath))
        {
            Console.WriteLine($"File not found: {javaFilePath}");
            return;
        }

        string javaSource = File.ReadAllText(javaFilePath);

        var statements = ExtractQueries(javaSource, StatementCallRegex);
        SaveJson(statements, Path.Combine(fixturesDir, "trino_statements.json"));
        Console.WriteLine($"Extrahierte Statements: {statements.Count}");

        var expressions = ExtractQueries(javaSource, ExpressionCallRegex);
        SaveJson(expressions, Path.Combine(fixturesDir, "trino_expressions.json"));
        Console.WriteLine($"Extrahierte Expressions: {expressions.Count}");

        var invalidStatements = ExtractQueries(javaSource, StatementFailsCallRegex);
        SaveJson(invalidStatements, Path.Combine(fixturesDir, "trino_statements_invalid.json"));
        Console.WriteLine($"Extrahierte Invalid Statements: {invalidStatements.Count}");

        var invalidExpressions = ExtractQueries(javaSource, ExpressionFailsCallRegex);
        SaveJson(invalidExpressions, Path.Combine(fixturesDir, "trino_expressions_invalid.json"));
        Console.WriteLine($"Extrahierte Invalid Expressions: {invalidExpressions.Count}");
    }

    private static void SaveJson(List<string> items, string path)
    {
        string? dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        File.WriteAllText(path, JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static string UnescapeJavaString(string input)
    {
        try
        {
            return Regex.Unescape(input);
        }
        catch
        {
            return input
                .Replace("\\\"", "\"")
                .Replace("\\'", "'")
                .Replace("\\n", "\n")
                .Replace("\\r", "\r")
                .Replace("\\t", "\t")
                .Replace("\\\\", "\\");
        }
    }
}
