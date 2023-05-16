using System.Text;
using System.Security.Cryptography;

using Newtonsoft.Json;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace DigitalSignature;

class Program
{
    static void Main(string[] args)
    {
        // data
        var myData = new
        {
            message = "test"
        };
        var keyPair = GenerateKeyPair();

        var privateKey = keyPair.Private as ECPrivateKeyParameters;
        var publicKey = keyPair.Public as ECPublicKeyParameters;

        var generator = new ECKeyPairGenerator("ECDSA");

        var serverPublicKey = "0461f54fb3ae429870af72922661935c4334423bc848896c9cdf0f24747f6e77acdcd95e6b40305ca6528780b309e7a627f85086a4d1528e7b6af16b82ebc8e7c5"; // public key from `GET /player/key/request`

        Console.WriteLine($"Private key: {ToHex(privateKey.D.ToByteArrayUnsigned())}");
        Console.WriteLine($"Public key: {ToHex(publicKey.Q.GetEncoded())}");

        string jsonData = JsonConvert.SerializeObject(myData);
        string privateKeyStr = ToHex(privateKey.D.ToByteArrayUnsigned()).ToString();

        IBasicAgreement aKeyAgree = AgreementUtilities.GetBasicAgreement("ECDH");
        aKeyAgree.Init(privateKey);

        var curve = ECNamedCurveTable.GetByName("secp256k1");
        var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(
            domainParams.Curve.DecodePoint(HexToBytes(serverPublicKey)), domainParams);
        // byte[] sharedKey = aKeyAgree.CalculateAgreement(ecPublicKeyParameters).ToByteArray();
        BigInteger agreementValue = aKeyAgree.CalculateAgreement(ecPublicKeyParameters);
        byte[] sharedKey = BigIntegers.AsUnsignedByteArray(aKeyAgree.GetFieldSize(), agreementValue);

        string signature = GetHMAC(Newtonsoft.Json.JsonConvert.SerializeObject(myData).ToString(), ToHex(sharedKey));
        Console.WriteLine($"Shared key: {ToHex(sharedKey)}");
        Console.WriteLine($"Signature: {signature}");
        Console.WriteLine($"Serialized Data: {Newtonsoft.Json.JsonConvert.SerializeObject(myData).ToString()}");

    }

    static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var curve = ECNamedCurveTable.GetByName("secp256k1");
        var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        var secureRandom = new SecureRandom();
        var keyParams = new ECKeyGenerationParameters(domainParams, secureRandom);

        var generator = new ECKeyPairGenerator("ECDH");
        generator.Init(keyParams);
        var keyPair = generator.GenerateKeyPair();

        return keyPair;
    }
    public static string ToHex(byte[] bytes)
    {
        char[] c = new char[bytes.Length * 2];

        byte b;

        for (int bx = 0, cx = 0; bx < bytes.Length; ++bx, ++cx)
        {
            b = ((byte)(bytes[bx] >> 4));
            c[cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);

            b = ((byte)(bytes[bx] & 0x0F));
            c[++cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);
        }

        return new string(c);
    }

    public static byte[] HexToBytes(string str)
    {
        if (str.Length == 0 || str.Length % 2 != 0)
            return new byte[0];

        byte[] buffer = new byte[str.Length / 2];
        char c;
        for (int bx = 0, sx = 0; bx < buffer.Length; ++bx, ++sx)
        {
            // Convert first half of byte
            c = str[sx];
            buffer[bx] = (byte)((c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0')) << 4);

            // Convert second half of byte
            c = str[++sx];
            buffer[bx] |= (byte)(c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0'));
        }

        return buffer;
    }
    private static string GetHMAC(string text, string key)
    {
        Encoding ascii = Encoding.ASCII;
        HMACSHA256 hmac = new HMACSHA256(HexToBytes(key));
        return ToHex(hmac.ComputeHash(ascii.GetBytes(text)));
    }
}