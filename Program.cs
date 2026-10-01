namespace TrinoSqlEngine;

using System;
using System.IO;
using Antlr4.Runtime.Tree;

public static class Program
{
    public static void RunDemo(string[] args)
    {
        Console.WriteLine("=== TrinoSqlEngine (.NET 10 / ANTLR4) ===");

        // 1. RLS Pipeline Test (Schritt 8)
        Console.WriteLine("\n[1] Führe RLS-Rewriting Pipeline aus:");
        var engine = new FastSqlEngine();
        var query = "SELECT id, amount FROM orders WHERE amount > 100".AsMemory();

        var (tree, tokens) = engine.Parse(query);

        var rewriter = new RlsListener(tokens);
        ParseTreeWalker.Default.Walk(rewriter, tree);

        string securedQuery = rewriter.GetSecuredSql();
        Console.WriteLine($"Original Query: {query}");
        Console.WriteLine($"Secured Query:  {securedQuery}");

        // 2. Extrahiere Trino Tests falls vorhanden
        string rawJavaFile = Path.Combine(AppContext.BaseDirectory, "Fixtures", "RawJava", "TestSqlParser.java");
        if (!File.Exists(rawJavaFile))
        {
            rawJavaFile = Path.Combine(Directory.GetCurrentDirectory(), "Fixtures", "RawJava", "TestSqlParser.java");
        }

        if (File.Exists(rawJavaFile))
        {
            Console.WriteLine("\n[2] Extrahiere Testsuiten aus TestSqlParser.java:");
            string fixturesDir = Path.Combine(Directory.GetCurrentDirectory(), "Fixtures");
            TrinoTestExtractor.ExtractAll(rawJavaFile, fixturesDir);
        }
        else
        {
            Console.WriteLine($"\n[2] RawJava-Testdatei nicht gefunden unter: {rawJavaFile}");
        }
    }
}
