using System;
using System.Numerics;
using System.Security.Cryptography;

namespace SRP
{
    public class SRPClient : SRP
    {
        public SRPClient(GroupParameter group, HashAlgorithm hashAlgorithm) :
            base(group, hashAlgorithm)
        {

        }

        /// <summary>
        /// A = g^a % N
        /// </summary>
        /// <param name="a"></param>
        /// <returns></returns>
        public byte[] Compute_A(BigInteger a)
        {
            var A = BigInteger.ModPow(Group.g_Big, a, Group.N_Big);
            return A.ToBytes();
        }

        /// <summary>
        /// <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
        /// </summary>
        /// <param name="B"></param>
        /// <param name="k"></param>
        /// <param name="u"></param>
        /// <param name="a"></param>
        /// <param name="x"></param>
        /// <returns></returns>
        public BigInteger Compute_S(BigInteger B, BigInteger k, BigInteger u, BigInteger a, BigInteger x)
        {
            if (B % Group.N_Big == BigInteger.Zero)
            {
                throw new Exception("B mod N == 0");
            }

            var v = BigInteger.ModPow(Group.g_Big, x, Group.N_Big);

            // RFC says it should be (B - (k * g^x)) ^ (a + (u * x)) % N
            // but this is the tricky part that we should subtract the k*v%N from N then add to B. I don't know why?
            var S = BigInteger.ModPow(B + (Group.N_Big - (k * v) % Group.N_Big), a + u * x, Group.N_Big);

            return S;
        }
    }
}
