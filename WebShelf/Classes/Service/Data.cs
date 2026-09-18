using System.Text;

namespace WebShelf.Classes.Service;

internal static class Data
{
    internal static string ConfigFile = Path.Combine(AppContext.BaseDirectory, "Server.conf");

    internal static DC.Domain? Domain = null;
    internal static string? GUID = null;

    internal static readonly Dictionary<string, string[]> sourceArray = new() {
        {"Domain", ["domainname", "domainuser", "domainpass"] },
        {"GUID", ["guid"] },
    };

    internal static bool ReadConfig()
    {
        bool result = true;

        Dictionary<string, string> config = [];

        if (File.Exists(ConfigFile))
        {
            try
            {
                string? s;
                using var f = new StreamReader(ConfigFile, Encoding.GetEncoding("utf-8"));

                while ((s = f.ReadLine()?.Trim()) is not null)
                {
                    if ((s != string.Empty) && (s.Length > 1) && (s[0] != '#'))
                    {
                        string[] substrings = s.Split('=');
                        if (substrings.Length == 2) config.Add(substrings[0], substrings[1]);
                    }
                }

                if (sourceArray["Domain"].All(config.ContainsKey)) Domain = new(config["domainname"], config["domainuser"], config["domainpass"]);
                if (sourceArray["GUID"].All(config.ContainsKey)) GUID = config["guid"];
            }
            catch
            {
                result = false;
            }
        }

        return result;
    }
}
