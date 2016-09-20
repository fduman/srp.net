using System;
using System.Numerics;
using System.Security.Cryptography;

namespace SRP
{
    public class SRPServer : SRP
    {
        public SRPServer(GroupParameter group, HashAlgorithm hashAlgorithm) : 
            base(group, hashAlgorithm)
        {

        }

        /// <summary>
        /// B = k*v + g^b % N
        /// </summary>
        /// <param name="v"></param>
        /// <param name="k"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public BigInteger Compute_B(BigInteger v, BigInteger k, BigInteger b)
        {
            var B = (k * v + BigInteger.ModPow(Group.g_Big, b, Group.N_Big)) % Group.N_Big;
            return B;
        }

        /// <summary>
        /// <premaster secret> = (A * v^u) ^ b % N
        /// </summary>
        /// <param name="A"></param>
        /// <param name="v"></param>
        /// <param name="u"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public BigInteger Compute_S(BigInteger A, BigInteger v, BigInteger u, BigInteger b)
        {
            if (A % Group.N_Big == BigInteger.Zero)
            {
                throw new Exception("A mod N == 0");
            }

            var S = BigInteger.ModPow(A * BigInteger.ModPow(v, u, Group.N_Big), b, Group.N_Big);
            return S;
        }

    }
}
