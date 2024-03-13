using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ClientLibrary.Helpers
{
    public static class Serializations
    {
        public static string Serialize<T>(T obj)
        {
            return JsonSerializer.Serialize(obj);
        }

        public static T Deserialize<T>(string json)
        {
            return JsonSerializer.Deserialize<T>(json);
        }

        public static IList<T> DeseriaalizeList<T>(string json)
        {
            return JsonSerializer.Deserialize<IList<T>>(json);
        }
    }
}
