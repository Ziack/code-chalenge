using System;
using System.Linq;
using System.Collections;

public class Program
{
    public static void Main()
    {
        var input = "abcc";
        var k = 2;
        var uniqueLetters = input.Distinct();
        var result = GetPermutations(uniqueLetters, k);

        foreach (var item in result)
        {
            Console.WriteLine(new String(item.Distinct().ToArray()));
        }
        Console.WriteLine(result.Count());
        Console.ReadLine();
    }

    static IEnumerable<IEnumerable<T>> GetPermutations<T>(IEnumerable<T> items, int count)
    {
        int i = 0;
        foreach (var item in items)
        {
            if (count == 1)
                yield return new T[] { item };
            else
            {
                foreach (var result in GetPermutations(items.Skip(i + 1), count - 1))
                    yield return new T[] { item }.Concat(result);
            }

            ++i;
        }
    }
}