using System;
using System.Numerics;

namespace SRP
{
    public class GroupParameter
    {
        private BigInteger primeBigInteger;
        private BigInteger generatorBigInteger;

        public GroupParameter(byte[] prime, byte[] generator, int keyLength)
        {
            if (prime == null || prime.Length == 0)
            {
                throw new ArgumentNullException(nameof(prime));
            }

            if (generator == null || generator.Length == 0)
            {
                throw new ArgumentNullException(nameof(generator));
            }

            N = prime;
            g = generator;
            KeyLength = keyLength;
        }

        public byte[] N { get; private set; }

        public byte[] g { get; private set; }

        public int KeyLength { get; private set; }

        public BigInteger N_Big
        {
            get
            {
                if (primeBigInteger.IsZero)
                {
                    primeBigInteger = N.ToBigInteger();
                }

                return primeBigInteger;
            }
        }

        public BigInteger g_Big
        {
            get
            {
                if (generatorBigInteger.IsZero)
                {
                    generatorBigInteger = g.ToBigInteger();
                }

                return generatorBigInteger;
            }
        }
    }
}
