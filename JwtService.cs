using System;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;

namespace Security.Jwt;

public class JwtService : IJwtService
{
    IPasswordProvider provider;
    public JwtService(IPasswordProvider provider)
    {
        this.provider = provider;
    }
    public string GetToken<T>(T obj)
    {
        var header = getJsonHeader();

        var json = JsonSerializer.Serialize(obj);
        var payload = this.jsonToBase64(json);

        var signature = this.getSignature(header, payload);

        return $"{header}.{payload}.{signature}";
    }

    public T Validate<T>(string jwt)
        where T : class
    {
        var jwtlist = jwt.Split('.');
        var signature = getSignature(jwtlist[0], jwtlist[1]);
        if (signature != jwtlist[2])
            return null;

        var payloadJson = this.base64ToJson(jwtlist[1]);
        var obj = JsonSerializer.Deserialize<T>(payloadJson);
        return obj;
    }

    private string base64ToJson(string base64)
    {
        var paddingBase64 = addPadding(base64);
        var bytes = Convert.FromBase64String(paddingBase64);
        var json = Encoding.UTF8.GetString(bytes);
        return json;
    }

    private string getSignature(string header, string payload)
    {
        var password = this.provider.ProvidePassword();
        var data = header + payload + password;
        var signature = this.applyHash(data);
        return signature;
    }

    private string applyHash(string str)
    {
        using var sha = SHA256.Create(); //using faz o dispose automatico no final da func
        var bytes = Encoding.UTF8.GetBytes(str);
        var hashBytes = sha.ComputeHash(bytes);
        var hash = Convert.ToBase64String(hashBytes);
        var unpadHash = this.removePadding(hash);
        return unpadHash;
    }

    private string getJsonHeader()
    {
        string header = """
            {
                "alg": "HS256",
                "typ": "JWT"
            }
            """;
        var base64 = this.jsonToBase64(header);
        return base64;
    }

    private string jsonToBase64(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var base64 = Convert.ToBase64String(bytes);
        var unpadBase64 = this.removePadding(base64);
        return unpadBase64;
    }

    private string removePadding(string base64)
    {
        var unpaddingBase64 = base64.Replace("=","");
        return unpaddingBase64;
    }

    private string addPadding(string base64)
    {
        int bits = 6* base64.Length;
        while (bits % 8 != 0)
        {
            bits += 6;
            base64 += "=";
        }
        return base64;
    }
}