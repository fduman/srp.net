using System;
using System.Numerics;
using System.Linq;

namespace SRP
{
    public static class UtilExtensions
    {
        public static bool CheckEquals(this byte[] source, byte[] target)
        {
            return source.SequenceEqual(target);
        }

        public static byte[] ToByteArray(this string hexString)
        {
            hexString = hexString.Replace(" ", "");
            int NumberChars = hexString.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return bytes;
        }

        public static BigInteger ToBigInteger(this byte[] data)
        {
            return new BigInteger(data.Reverse().Concat(new byte[] { 0 }).ToArray());
        }

        public static byte[] ToBytes(this BigInteger value)
        {
            var valueArray = value.ToByteArray();

            if (valueArray[valueArray.Length - 1] != 0)
            {
                Array.Reverse(valueArray);
                return valueArray;
            }

            var result = new byte[valueArray.Length - 1];
            Array.Copy(valueArray, result, valueArray.Length - 1);
            Array.Reverse(result);
            return result;
        }
    }
}
