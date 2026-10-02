namespace TrinoSqlEngine;

using Antlr4.Runtime.Atn;
using Antlr4.Runtime.Dfa;

public static class SharedParserCache
{
    public static readonly ATN Atn;
    public static readonly DFA[] DecisionToDfa;
    public static readonly PredictionContextCache ContextCache = new();

    static SharedParserCache()
    {
        // Dummy-Parser initialisieren, um statisches ATN zu extrahieren
        var dummyParser = new SqlBaseParser(null);
        Atn = dummyParser.Atn;
        DecisionToDfa = new DFA[Atn.NumberOfDecisions];
        for (int i = 0; i < Atn.NumberOfDecisions; i++)
        {
            DecisionToDfa[i] = new DFA(Atn.GetDecisionState(i), i);
        }
    }
}
