using Datagrammer.Quic.Protocol.Error;
using System;
using System.Security.Cryptography;

namespace Datagrammer.Quic.Protocol.Tls.Curves
{
    public class X25519 : ICurve
    {
        private const int PointSize = 32;
        private const int ScalarSize = 32;

        private const int C_A = 486662;
        private const int C_A24 = (C_A + 2) / 4;

        private static void DecodeScalar(ReadOnlySpan<byte> k, int kOff, Span<uint> n)
        {
            for (int i = 0; i < 8; ++i)
            {
                n[i] = X25519Field.Decode32(k, kOff + i * 4);
            }

            n[0] &= 0xFFFFFFF8U;
            n[7] &= 0x7FFFFFFFU;
            n[7] |= 0x40000000U;
        }

        private static void GeneratePrivateKey(RNGCryptoServiceProvider random, Span<byte> k)
        {
            random.GetBytes(k);

            k[0] &= 0xF8;
            k[ScalarSize - 1] &= 0x7F;
            k[ScalarSize - 1] |= 0x40;
        }

        private static void GeneratePublicKey(ReadOnlySpan<byte> k, int kOff, Span<byte> r, int rOff)
        {
            ScalarMultBase(k, kOff, r, rOff);
        }

        private static void PointDouble(Span<int> x, Span<int> z)
        {
            Span<int> A = stackalloc int[X25519Field.Size];
            Span<int> B = stackalloc int[X25519Field.Size];

            X25519Field.Apm(x, z, A, B);
            X25519Field.Sqr(A, A);
            X25519Field.Sqr(B, B);
            X25519Field.Mul(A, B, x);
            X25519Field.Sub(A, B, A);
            X25519Field.Mul(A, C_A24, z);
            X25519Field.Add(z, B, z);
            X25519Field.Mul(z, A, z);
        }

        private static void ScalarMult(ReadOnlySpan<byte> k, int kOff, ReadOnlySpan<byte> u, int uOff, Span<byte> r, int rOff)
        {
            Span<uint> n = stackalloc uint[8]; 
            
            DecodeScalar(k, kOff, n);

            Span<int> x1 = stackalloc int[X25519Field.Size];
            X25519Field.Decode(u, uOff, x1);
            Span<int> x2 = stackalloc int[X25519Field.Size];
            X25519Field.Copy(x1, 0, x2, 0);
            Span<int> z2 = stackalloc int[X25519Field.Size];
            z2[0] = 1;
            Span<int> x3 = stackalloc int[X25519Field.Size];
            x3[0] = 1;
            Span<int> z3 = stackalloc int[X25519Field.Size];

            Span<int> t1 = stackalloc int[X25519Field.Size];
            Span<int> t2 = stackalloc int[X25519Field.Size];

            int bit = 254, swap = 1;

            do
            {
                X25519Field.Apm(x3, z3, t1, x3);
                X25519Field.Apm(x2, z2, z3, x2);
                X25519Field.Mul(t1, x2, t1);
                X25519Field.Mul(x3, z3, x3);
                X25519Field.Sqr(z3, z3);
                X25519Field.Sqr(x2, x2);

                X25519Field.Sub(z3, x2, t2);
                X25519Field.Mul(t2, C_A24, z2);
                X25519Field.Add(z2, x2, z2);
                X25519Field.Mul(z2, t2, z2);
                X25519Field.Mul(x2, z3, x2);

                X25519Field.Apm(t1, x3, x3, z3);
                X25519Field.Sqr(x3, x3);
                X25519Field.Sqr(z3, z3);
                X25519Field.Mul(z3, x1, z3);

                --bit;

                int word = bit >> 5, shift = bit & 0x1F;
                int kt = (int)(n[word] >> shift) & 1;
                swap ^= kt;
                X25519Field.CSwap(swap, x2, x3);
                X25519Field.CSwap(swap, z2, z3);
                swap = kt;
            }
            while (bit >= 3);

            for (int i = 0; i < 3; ++i)
            {
                PointDouble(x2, z2);
            }

            X25519Field.Inv(z2, z2);
            X25519Field.Mul(x2, z2, x2);

            X25519Field.Normalize(x2);
            X25519Field.Encode(x2, r, rOff);
        }

        private static void ScalarMultBase(ReadOnlySpan<byte> k, int kOff, Span<byte> r, int rOff)
        {
            Span<int> y = stackalloc int[X25519Field.Size];
            Span<int> z = stackalloc int[X25519Field.Size];

            Ed25519.ScalarMultBaseYZ(k, kOff, y, z);

            X25519Field.Apm(z, y, y, z);

            X25519Field.Inv(z, z);
            X25519Field.Mul(y, z, y);

            X25519Field.Normalize(y);
            X25519Field.Encode(y, r, rOff);
        }

        public ReadOnlyMemory<byte> GeneratePrivateKey()
        {
            var random = new RNGCryptoServiceProvider();
            var buffer = new byte[ScalarSize];

            GeneratePrivateKey(random, buffer);

            return buffer;
        }

        public ReadOnlyMemory<byte> GeneratePublicKey(ReadOnlySpan<byte> privateKey)
        {
            var buffer = new byte[ScalarSize];

            GeneratePublicKey(privateKey, 0, buffer, 0);

            return buffer;
        }

        public ReadOnlyMemory<byte> GenerateSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
        {
            var buffer = new byte[ScalarSize];

            ScalarMult(privateKey, 0, publicKey, 0, buffer, 0);

            return buffer;
        }
    }
}
