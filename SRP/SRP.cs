using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SRP
{
    public abstract class SRP
    {
        public static readonly GroupParameter Group_1024 = new GroupParameter(
            ("EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C" +
             "9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4" +
             "8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29" +
             "7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A" +
             "FD5138FE 8376435B 9FC61D2F C0EB06E3").ToByteArray(),
            new byte[] { 2 },
            1024);

        public static readonly GroupParameter Group_3072 = new GroupParameter(
            ("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08" +
             "8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B" +
             "302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9" +
             "A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6" +
             "49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8" +
             "FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" +
             "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C" +
             "180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718" +
             "3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D" +
             "04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D" +
             "B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226" +
             "1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C" +
             "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC" +
             "E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF").ToByteArray(),
            new byte[] { 5 },
            3072);

        private readonly GroupParameter group;
        private readonly HashAlgorithm hashAlgorithm;
        private byte[] k;

        protected SRP(GroupParameter group, HashAlgorithm hashAlgorithm)
        {
            this.group = group;
            this.hashAlgorithm = hashAlgorithm;
        }

        protected GroupParameter Group
        {
            get { return group; }
        }

        protected HashAlgorithm HashAlgorithm
        {
            get { return hashAlgorithm; }
        }

        protected byte[] Value_k
        {
            get
            {
                if (k == null)
                {
                    k = Compute_k();
                }

                return k;
            }
        }

        protected byte[] Pad(byte[] value)
        {
            var result = new byte[Group.KeyLength / 8];
            value.CopyTo(result, result.Length - value.Length);
            return result;
        }

        /// <summary>
        /// k = H(N | PAD(g))
        /// </summary>
        /// <returns></returns>
        public byte[] Compute_k()
        {
            byte[] padded_g = Pad(Group.g);
            byte[] hashk = HashAlgorithm.ComputeHash(Group.N.Concat(padded_g).ToArray());
            return hashk;
        }

        /// <summary>
        /// x = H(s | H(I | ":" | P))
        /// </summary>
        /// <param name="s"></param>
        /// <param name="I"></param>
        /// <param name="P"></param>
        /// <returns></returns>
        public byte[] Compute_x(byte[] s, string I, string P)
        {
            byte[] hashIP = HashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(I + ":" + P));
            byte[] hashx = HashAlgorithm.ComputeHash(s.Concat(hashIP).ToArray());
            return hashx;
        }

        /// <summary>
        /// v = g^x % N
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        public BigInteger Compute_v(BigInteger x)
        {
            var v = BigInteger.ModPow(Group.g_Big, x, Group.N_Big);
            return v;
        }

        /// <summary>
        /// u = H(PAD(A) | PAD(B))
        /// </summary>
        /// <param name="A"></param>
        /// <param name="B"></param>
        /// <returns></returns>
        public byte[] Compute_u(byte[] A, byte[] B)
        {
            byte[] paddedA = Pad(A);
            byte[] paddedB = Pad(B);
            byte[] hashOfA_B = HashAlgorithm.ComputeHash(paddedA.Concat(paddedB).ToArray());
            return hashOfA_B;
        }

        /// <summary>
        /// K = H_Interleave(S)
        /// </summary>
        /// <param name="S"></param>
        /// <returns></returns>
        public byte[] Compute_K(byte[] S)
        {
            var K = HashAlgorithm.ComputeHash(S);
            return K;
        }

        /// <summary>
        /// H(H(N) XOR H(g) | H(I) | s | A | B | K)
        /// </summary>
        /// <param name="I"></param>
        /// <param name="s"></param>
        /// <param name="A"></param>
        /// <param name="B"></param>
        /// <param name="K"></param>
        /// <returns></returns>
        public byte[] Compute_M1(string I, byte[] s, byte[] A, byte[] B, byte[] K)
        {
            byte[] hash_N = HashAlgorithm.ComputeHash(Group.N);
            byte[] hash_g = HashAlgorithm.ComputeHash(Group.g);

            for (int i = 0; i < hash_N.Length; i++)
            {
                hash_N[i] ^= hash_g[i];
            }

            byte[] hash_I = HashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(I));

            byte[] M1 = HashAlgorithm.ComputeHash(hash_N.Concat(hash_I).Concat(s).Concat(A).Concat(B).Concat(K).ToArray());
            return M1;
        }

        /// <summary>
        /// H(A | M1 | K)
        /// </summary>
        /// <param name="A"></param>
        /// <param name="M1"></param>
        /// <param name="K"></param>
        /// <returns></returns>
        public byte[] Compute_M2(byte[] A, byte[] M1, byte[] K)
        {
            byte[] M2 = HashAlgorithm.ComputeHash(A.Concat(M1).Concat(K).ToArray());
            return M2;
        }
    }
}
