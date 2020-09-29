using System;

namespace Datagrammer.Quic.Protocol.Tls.Curves
{
    public static class Ed25519
    {
        private static readonly uint[] L = 
        { 
            0x5CF5D3EDU, 
            0x5812631AU, 
            0xA2F79CD6U, 
            0x14DEF9DEU, 
            0x00000000U, 
            0x00000000U, 
            0x00000000U, 
            0x10000000U 
        };

        private static readonly int[] B_x = 
        { 
            0x0325D51A, 
            0x018B5823, 
            0x007B2C95, 
            0x0304A92D, 
            0x00D2598E, 
            0x01D6DC5C,
            0x01388C7F, 
            0x013FEC0A, 
            0x029E6B72, 
            0x0042D26D 
        };

        private static readonly int[] B_y = 
        { 
            0x02666658, 
            0x01999999, 
            0x00666666, 
            0x03333333, 
            0x00CCCCCC, 
            0x02666666,
            0x01999999, 
            0x00666666, 
            0x03333333, 
            0x00CCCCCC, 
        };

        private static readonly int[] C_d = 
        { 
            0x035978A3, 
            0x02D37284, 
            0x018AB75E, 
            0x026A0A0E, 
            0x0000E014, 
            0x0379E898,
            0x01D01E5D, 
            0x01E738CC, 
            0x03715B7F, 
            0x00A406D9 
        };

        private static readonly int[] C_d2 = 
        { 
            0x02B2F159, 
            0x01A6E509, 
            0x01156EBD, 
            0x00D4141D, 
            0x0001C029, 
            0x02F3D130,
            0x03A03CBB, 
            0x01CE7198, 
            0x02E2B6FF, 
            0x00480DB3 
        };

        private static readonly int[] C_d4 = 
        { 
            0x0165E2B2, 
            0x034DCA13, 
            0x002ADD7A, 
            0x01A8283B, 
            0x00038052, 
            0x01E7A260,
            0x03407977, 
            0x019CE331, 
            0x01C56DFF, 
            0x00901B67 
        };

        private const int ScalarUints = 8;
        private const int ScalarBytes = ScalarUints * 4;
        private const int PrecompSpacing = 8;
        private const int PrecompTeeth = 4;
        private const int PrecompBlocks = 8;
        private const int PrecompPoints = 1 << (PrecompTeeth - 1);
        private const int PrecompMask = PrecompPoints - 1;

        private static int[] precompBase = null;

        private class PointAccum
        {
            public int[] x = new int[X25519Field.Size];
            public int[] y = new int[X25519Field.Size];
            public int[] z = new int[X25519Field.Size];
            public int[] u = new int[X25519Field.Size];
            public int[] v = new int[X25519Field.Size];
        }

        private class PointExt
        {
            public int[] x = new int[X25519Field.Size];
            public int[] y = new int[X25519Field.Size];
            public int[] z = new int[X25519Field.Size];
            public int[] t = new int[X25519Field.Size];
        }

        private class PointPrecomp
        {
            public int[] ypx_h = new int[X25519Field.Size];
            public int[] ymx_h = new int[X25519Field.Size];
            public int[] xyd = new int[X25519Field.Size];
        }

        static Ed25519()
        {
            Precompute();
        }

        public static void ScalarMultBaseYZ(ReadOnlySpan<byte> k, int kOff, Span<int> y, Span<int> z)
        {
            Span<byte> n = stackalloc byte[ScalarBytes];

            PruneScalar(k, kOff, n);
            ScalarMultBase(n, y, z);
        }

        private static int CheckPoint(Span<int> x, Span<int> y, Span<int> z)
        {
            Span<int> t = stackalloc int[X25519Field.Size];
            Span<int> u = stackalloc int[X25519Field.Size];
            Span<int> v = stackalloc int[X25519Field.Size];
            Span<int> w = stackalloc int[X25519Field.Size];

            X25519Field.Sqr(x, u);
            X25519Field.Sqr(y, v);
            X25519Field.Sqr(z, w);
            X25519Field.Mul(u, v, t);
            X25519Field.Sub(v, u, v);
            X25519Field.Mul(v, w, v);
            X25519Field.Sqr(w, w);
            X25519Field.Mul(t, C_d, t);
            X25519Field.Add(t, w, t);
            X25519Field.Sub(t, v, t);
            X25519Field.Normalize(t);

            return X25519Field.IsZero(t);
        }

        private static void PruneScalar(ReadOnlySpan<byte> n, int nOff, Span<byte> r)
        {
            n.Slice(nOff, ScalarBytes).CopyTo(r);

            r[0] &= 0xF8;
            r[ScalarBytes - 1] &= 0x7F;
            r[ScalarBytes - 1] |= 0x40;
        }

        private static void ScalarMultBase(Span<byte> k, Span<int> y, Span<int> z)
        {
            Span<int> rx = stackalloc int[X25519Field.Size];
            Span<int> ry = stackalloc int[X25519Field.Size];
            Span<int> rz = stackalloc int[X25519Field.Size];
            Span<int> ru = stackalloc int[X25519Field.Size];
            Span<int> rv = stackalloc int[X25519Field.Size];

            X25519Field.Zero(rx);
            X25519Field.One(ry);
            X25519Field.One(rz);
            X25519Field.Zero(ru);
            X25519Field.One(rv);

            Span<uint> n = stackalloc uint[ScalarUints];

            DecodeScalar(k, 0, n);

            {
                uint c1 = CAdd(ScalarUints, ~(int)n[0] & 1, n, L, n);
                uint c2 = ShiftDownBit(ScalarUints, n, 1U);

                for (int i = 0; i < ScalarUints; ++i)
                {
                    n[i] = Shuffle2(n[i]);
                }
            }

            Span<int> pypx_h = stackalloc int[X25519Field.Size];
            Span<int> pymx_h = stackalloc int[X25519Field.Size];
            Span<int> pxyd = stackalloc int[X25519Field.Size];

            int cOff = (PrecompSpacing - 1) * PrecompTeeth;

            for (; ; )
            {
                for (int b = 0; b < PrecompBlocks; ++b)
                {
                    uint w = n[b] >> cOff;
                    int sign = (int)(w >> (PrecompTeeth - 1)) & 1;
                    int abs = ((int)w ^ -sign) & PrecompMask;

                    int off = b * PrecompPoints * 3 * X25519Field.Size;

                    for (int i = 0; i < PrecompPoints; ++i)
                    {
                        int cond = ((i ^ abs) - 1) >> 31;
                        X25519Field.CMov(cond, precompBase, off, pypx_h, 0); off += X25519Field.Size;
                        X25519Field.CMov(cond, precompBase, off, pymx_h, 0); off += X25519Field.Size;
                        X25519Field.CMov(cond, precompBase, off, pxyd, 0); off += X25519Field.Size;
                    }

                    X25519Field.CSwap(sign, pypx_h, pymx_h);
                    X25519Field.CNegate(sign, pxyd);

                    Span<int> A = stackalloc int[X25519Field.Size];
                    Span<int> B = stackalloc int[X25519Field.Size];
                    Span<int> C = stackalloc int[X25519Field.Size];
                    Span<int> E = ru;
                    Span<int> F = stackalloc int[X25519Field.Size];
                    Span<int> G = stackalloc int[X25519Field.Size];
                    Span<int> H = rv;

                    X25519Field.Apm(ry, rx, B, A);
                    X25519Field.Mul(A, pymx_h, A);
                    X25519Field.Mul(B, pypx_h, B);
                    X25519Field.Mul(ru, rv, C);
                    X25519Field.Mul(C, pxyd, C);
                    X25519Field.Apm(B, A, H, E);
                    X25519Field.Apm(rz, C, G, F);
                    X25519Field.Carry(G);
                    X25519Field.Mul(E, F, rx);
                    X25519Field.Mul(G, H, ry);
                    X25519Field.Mul(F, G, rz);
                }

                if ((cOff -= PrecompTeeth) < 0)
                {
                    break;
                }

                Span<int> pdA = stackalloc int[X25519Field.Size];
                Span<int> pdB = stackalloc int[X25519Field.Size];
                Span<int> pdC = stackalloc int[X25519Field.Size];
                Span<int> pdE = ru;
                Span<int> pdF = stackalloc int[X25519Field.Size];
                Span<int> pdG = stackalloc int[X25519Field.Size];
                Span<int> pdH = rv;

                X25519Field.Sqr(rx, pdA);
                X25519Field.Sqr(ry, pdB);
                X25519Field.Sqr(rz, pdC);
                X25519Field.Add(pdC, pdC, pdC);
                X25519Field.Apm(pdA, pdB, pdH, pdG);
                X25519Field.Add(rx, ry, pdE);
                X25519Field.Sqr(pdE, pdE);
                X25519Field.Sub(pdH, pdE, pdE);
                X25519Field.Add(pdC, pdG, pdF);
                X25519Field.Carry(pdF);
                X25519Field.Mul(pdE, pdF, rx);
                X25519Field.Mul(pdG, pdH, ry);
                X25519Field.Mul(pdF, pdG, rz);
            }

            if (0 == CheckPoint(rx, ry, rz))
            {
                throw new InvalidOperationException();
            }
                
            X25519Field.Copy(ry, 0, y, 0);
            X25519Field.Copy(rz, 0, z, 0);
        }

        private static uint ShiftDownBit(int len, Span<uint> z, uint c)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = z[i];
                z[i] = (next >> 1) | (c << 31);
                c = next;
            }
            return c << 31;
        }

        private static uint CAdd(int len, int mask, Span<uint> x, Span<uint> y, Span<uint> z)
        {
            uint MASK = (uint)-(mask & 1);

            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + (y[i] & MASK);
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        private static uint Shuffle2(uint x)
        {
            uint t;
            t = (x ^ (x >> 7)) & 0x00AA00AAU; x ^= (t ^ (t << 7));
            t = (x ^ (x >> 14)) & 0x0000CCCCU; x ^= (t ^ (t << 14));
            t = (x ^ (x >> 4)) & 0x00F000F0U; x ^= (t ^ (t << 4));
            t = (x ^ (x >> 8)) & 0x0000FF00U; x ^= (t ^ (t << 8));
            return x;
        }

        private static void Precompute()
        {
            PointAccum p = new PointAccum();

            X25519Field.Copy(B_x, 0, p.x, 0);
            X25519Field.Copy(B_y, 0, p.y, 0);

            PointExtendXY(p);

            precompBase = new int[PrecompBlocks * PrecompPoints * 3 * X25519Field.Size];

            int off = 0;

            for (int b = 0; b < PrecompBlocks; ++b)
            {
                PointExt[] ds = new PointExt[PrecompTeeth];
                PointExt sum = new PointExt();
                PointSetNeutral(sum);

                for (int t = 0; t < PrecompTeeth; ++t)
                {
                    PointExt q = PointCopy(p);
                    PointAddVar(true, sum, q, sum);
                    PointDouble(p);

                    ds[t] = PointCopy(p);

                    if (b + t != PrecompBlocks + PrecompTeeth - 2)
                    {
                        for (int s = 1; s < PrecompSpacing; ++s)
                        {
                            PointDouble(p);
                        }
                    }
                }

                PointExt[] points = new PointExt[PrecompPoints];
                int k = 0;
                points[k++] = sum;

                for (int t = 0; t < (PrecompTeeth - 1); ++t)
                {
                    int size = 1 << t;
                    for (int j = 0; j < size; ++j, ++k)
                    {
                        PointAddVar(false, points[k - size], ds[t], points[k] = new PointExt());
                    }
                }

                for (int i = 0; i < PrecompPoints; ++i)
                {
                    PointExt q = points[i];

                    int[] x = new int[X25519Field.Size];
                    int[] y = new int[X25519Field.Size];

                    X25519Field.Add(q.z, q.z, x);
                    X25519Field.Inv(x, y);
                    X25519Field.Mul(q.x, y, x);
                    X25519Field.Mul(q.y, y, y);

                    PointPrecomp r = new PointPrecomp();
                    X25519Field.Apm(y, x, r.ypx_h, r.ymx_h);
                    X25519Field.Mul(x, y, r.xyd);
                    X25519Field.Mul(r.xyd, C_d4, r.xyd);

                    X25519Field.Normalize(r.ypx_h);
                    X25519Field.Normalize(r.ymx_h);

                    X25519Field.Copy(r.ypx_h, 0, precompBase, off); off += X25519Field.Size;
                    X25519Field.Copy(r.ymx_h, 0, precompBase, off); off += X25519Field.Size;
                    X25519Field.Copy(r.xyd, 0, precompBase, off); off += X25519Field.Size;
                }
            }
        }

        private static void PointAddVar(bool negate, PointExt p, PointExt q, PointExt r)
        {
            int[] A = new int[X25519Field.Size];
            int[] B = new int[X25519Field.Size];
            int[] C = new int[X25519Field.Size];
            int[] D = new int[X25519Field.Size];
            int[] E = new int[X25519Field.Size];
            int[] F = new int[X25519Field.Size];
            int[] G = new int[X25519Field.Size];
            int[] H = new int[X25519Field.Size];

            int[] c, d, f, g;
            if (negate)
            {
                c = D; d = C; f = G; g = F;
            }
            else
            {
                c = C; d = D; f = F; g = G;
            }

            X25519Field.Apm(p.y, p.x, B, A);
            X25519Field.Apm(q.y, q.x, d, c);
            X25519Field.Mul(A, C, A);
            X25519Field.Mul(B, D, B);
            X25519Field.Mul(p.t, q.t, C);
            X25519Field.Mul(C, C_d2, C);
            X25519Field.Mul(p.z, q.z, D);
            X25519Field.Add(D, D, D);
            X25519Field.Apm(B, A, H, E);
            X25519Field.Apm(D, C, g, f);
            X25519Field.Carry(g);
            X25519Field.Mul(E, F, r.x);
            X25519Field.Mul(G, H, r.y);
            X25519Field.Mul(F, G, r.z);
            X25519Field.Mul(E, H, r.t);
        }

        private static void PointExtendXY(PointAccum p)
        {
            X25519Field.One(p.z);
            X25519Field.Copy(p.x, 0, p.u, 0);
            X25519Field.Copy(p.y, 0, p.v, 0);
        }

        private static void PointSetNeutral(PointExt p)
        {
            X25519Field.Zero(p.x);
            X25519Field.One(p.y);
            X25519Field.One(p.z);
            X25519Field.Zero(p.t);
        }

        private static void DecodeScalar(Span<byte> k, int kOff, Span<uint> n)
        {
            Decode32(k, kOff, n, 0, ScalarUints);
        }

        private static void Decode32(Span<byte> bs, int bsOff, Span<uint> n, int nOff, int nLen)
        {
            for (int i = 0; i < nLen; ++i)
            {
                n[nOff + i] = X25519Field.Decode32(bs, bsOff + i * 4);
            }
        }

        private static void PointDouble(PointAccum r)
        {
            int[] A = new int[X25519Field.Size];
            int[] B = new int[X25519Field.Size];
            int[] C = new int[X25519Field.Size];
            int[] E = r.u;
            int[] F = new int[X25519Field.Size];
            int[] G = new int[X25519Field.Size];
            int[] H = r.v;

            X25519Field.Sqr(r.x, A);
            X25519Field.Sqr(r.y, B);
            X25519Field.Sqr(r.z, C);
            X25519Field.Add(C, C, C);
            X25519Field.Apm(A, B, H, G);
            X25519Field.Add(r.x, r.y, E);
            X25519Field.Sqr(E, E);
            X25519Field.Sub(H, E, E);
            X25519Field.Add(C, G, F);
            X25519Field.Carry(F);
            X25519Field.Mul(E, F, r.x);
            X25519Field.Mul(G, H, r.y);
            X25519Field.Mul(F, G, r.z);
        }

        private static PointExt PointCopy(PointAccum p)
        {
            PointExt r = new PointExt();
            X25519Field.Copy(p.x, 0, r.x, 0);
            X25519Field.Copy(p.y, 0, r.y, 0);
            X25519Field.Copy(p.z, 0, r.z, 0);
            X25519Field.Mul(p.u, p.v, r.t);
            return r;
        }
    }
}
