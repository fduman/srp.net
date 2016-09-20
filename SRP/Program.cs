using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace SRP
{
    class Program
    {
        static string expected_k = ("7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F").Replace(" ", "");
        static string expected_x = ("94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124").Replace(" ", "");
        static string expected_v =
            ("7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812" +
            "9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5" +
            "C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5" +
            "EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78" +
            "E955A5E2 9E7AB245 DB2BE315 E2099AFB").Replace(" ", "");

        static string expected_A =
            ("61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4" +
             "4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC" +
             "8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44" +
             "BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA" +
             "B349EF5D 76988A36 72FAC47B 0769447B").Replace(" ", "");

        static string expected_B =
            ("BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011" +
            "BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99" +
            "6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA" +
            "37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE" +
            "EB4012B7 D7665238 A8E3FB00 4B117B58").Replace(" ", "");

        static string expected_S =
            ("B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D" +
            "233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C" +
            "41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F" +
            "3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D" +
            "C346D7E4 74B29EDE 8A469FFE CA686E5A").Replace(" ", "");

        static string expected_u = ("CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019").Replace(" ", "");

        public static string ByteArrayToString(byte[] ba)
        {
            string hex = BitConverter.ToString(ba);
            return hex.Replace("-", "");
        }

        public static byte[] StringToByteArray(String hex)
        {
            hex = hex.Replace(" ", "");
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        static void Main(string[] args)
        {
            // Test RFC 5054 vectors

            var I = "alice";
            var P = "password123";
            byte[] s = StringToByteArray("BEB25379 D1A8581E B5A72767 3A2441EE");

            var hashAlgorithm = SHA1.Create();
            var groupParameter = SRP.Group_1024;

            var client = new SRPClient(groupParameter, hashAlgorithm);
            byte[] a = StringToByteArray("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393");
            var A = client.Compute_A(a.ToBigInteger());
            Debug.Assert(ByteArrayToString(A).Equals(expected_A));

            var server = new SRPServer(groupParameter, hashAlgorithm);

            var k = server.Compute_k();
            Debug.Assert(ByteArrayToString(k).Equals(expected_k));

            var x = server.Compute_x(s, I, P);
            Debug.Assert(ByteArrayToString(x).Equals(expected_x));

            var v = server.Compute_v(x.ToBigInteger());
            Debug.Assert(ByteArrayToString(v.ToBytes()).Equals(expected_v));

            byte[] b = StringToByteArray("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20");
            
            var B = server.Compute_B(v, k.ToBigInteger(), b.ToBigInteger());
            Debug.Assert(ByteArrayToString(B.ToBytes()).Equals(expected_B));

            var u = client.Compute_u(A, B.ToBytes());
            Debug.Assert(ByteArrayToString(u).Equals(expected_u));

            var client_S = client.Compute_S(B, k.ToBigInteger(), u.ToBigInteger(), a.ToBigInteger(), x.ToBigInteger());
            Debug.Assert(ByteArrayToString(client_S.ToBytes()).Equals(expected_S));

            var server_S = server.Compute_S(A.ToBigInteger(), v, u.ToBigInteger(), b.ToBigInteger());
            Debug.Assert(ByteArrayToString(server_S.ToBytes()).Equals(expected_S));

            var client_K = client.Compute_K(client_S.ToBytes());
            var server_K = server.Compute_K(server_S.ToBytes());

            Debug.Assert(client_K.CheckEquals(server_K));

            var client_M1 = client.Compute_M1(I, s, A, B.ToBytes(), client_K);

            var server_M1 = server.Compute_M1(I, s, A, B.ToBytes(), server_K);

            Debug.Assert(client_M1.CheckEquals(server_M1));

            var server_M2 = server.Compute_M2(A, server_M1, server_K);

            var client_M2 = client.Compute_M2(A, client_M1, client_K);

            Debug.Assert(server_M2.CheckEquals(client_M2));
        }
    }
}
