using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Datagrammer.Quic.Protocol.Tls.Ciphers
{
    public class AesEcbIntrinsicsCipher : ICipher
    {
        private const int KeyLength = 16;
        private const int MaskLength = 5;

        private Vector128<byte>[] roundKeys;

        public AesEcbIntrinsicsCipher(ReadOnlyMemory<byte> key)
        {
            if (key.Length != KeyLength)
            {
                throw new ArgumentOutOfRangeException(nameof(key));
            }

            Span<byte> buffer = stackalloc byte[key.Length];

            key.Span.CopyTo(buffer);

            roundKeys = KeyExpansion(buffer);
        }

        public int CreateMask(ReadOnlySpan<byte> sample, Span<byte> destination)
        {
            if (sample.Length < MaskLength)
            {
                throw new ArgumentOutOfRangeException(nameof(sample));
            }

            if (destination.Length < MaskLength)
            {
                throw new ArgumentOutOfRangeException(nameof(sample));
            }

            Span<byte> buffer = stackalloc byte[sample.Length];

            sample.CopyTo(buffer);

            Encrypt(buffer);

            buffer.Slice(0, MaskLength).CopyTo(destination);

            return MaskLength;
        }

        private void Encrypt(Span<byte> data)
        {
            Vector128<byte>[] keys = roundKeys;
            Span<Vector128<byte>> blocks = MemoryMarshal.Cast<byte, Vector128<byte>>(data);

            for (int i = 0; i < blocks.Length; i++)
            {
                Vector128<byte> b = blocks[i];

                b = Sse2.Xor(b, keys[0]);
                b = Aes.Encrypt(b, keys[1]);
                b = Aes.Encrypt(b, keys[2]);
                b = Aes.Encrypt(b, keys[3]);
                b = Aes.Encrypt(b, keys[4]);
                b = Aes.Encrypt(b, keys[5]);
                b = Aes.Encrypt(b, keys[6]);
                b = Aes.Encrypt(b, keys[7]);
                b = Aes.Encrypt(b, keys[8]);
                b = Aes.Encrypt(b, keys[9]);
                b = Aes.EncryptLast(b, keys[10]);

                blocks[i] = b;
            }
        }

        private void Decrypt(Span<byte> data)
        {
            Vector128<byte>[] keys = roundKeys;
            Span<Vector128<byte>> blocks = MemoryMarshal.Cast<byte, Vector128<byte>>(data);

            for (int i = 0; i < blocks.Length; i++)
            {
                Vector128<byte> b = blocks[i];

                b = Sse2.Xor(b, keys[10]);
                b = Aes.Decrypt(b, keys[19]);
                b = Aes.Decrypt(b, keys[18]);
                b = Aes.Decrypt(b, keys[17]);
                b = Aes.Decrypt(b, keys[16]);
                b = Aes.Decrypt(b, keys[15]);
                b = Aes.Decrypt(b, keys[14]);
                b = Aes.Decrypt(b, keys[13]);
                b = Aes.Decrypt(b, keys[12]);
                b = Aes.Decrypt(b, keys[11]);
                b = Aes.DecryptLast(b, keys[0]);

                blocks[i] = b;
            }
        }

        private Vector128<byte>[] KeyExpansion(Span<byte> key)
        {
            var keys = new Vector128<byte>[20];

            keys[0] = Unsafe.ReadUnaligned<Vector128<byte>>(ref key[0]);

            MakeRoundKey(keys, 1, 0x01);
            MakeRoundKey(keys, 2, 0x02);
            MakeRoundKey(keys, 3, 0x04);
            MakeRoundKey(keys, 4, 0x08);
            MakeRoundKey(keys, 5, 0x10);
            MakeRoundKey(keys, 6, 0x20);
            MakeRoundKey(keys, 7, 0x40);
            MakeRoundKey(keys, 8, 0x80);
            MakeRoundKey(keys, 9, 0x1b);
            MakeRoundKey(keys, 10, 0x36);

            for (int i = 1; i < 10; i++)
            {
                keys[10 + i] = Aes.InverseMixColumns(keys[i]);
            }

            return keys;
        }

        private void MakeRoundKey(Vector128<byte>[] keys, int i, byte rcon)
        {
            Vector128<byte> s = keys[i - 1];
            Vector128<byte> t = keys[i - 1];

            t = Aes.KeygenAssist(t, rcon);
            t = Sse2.Shuffle(t.AsUInt32(), 0xFF).AsByte();

            s = Sse2.Xor(s, Sse2.ShiftLeftLogical128BitLane(s, 4));
            s = Sse2.Xor(s, Sse2.ShiftLeftLogical128BitLane(s, 8));

            keys[i] = Sse2.Xor(s, t);
        }

        public static bool IsSupported
        {
#if DEBUG
            get => string.IsNullOrEmpty(Environment.GetEnvironmentVariable(Debug.NoAesVar)) && Aes.IsSupported;
#else
            get => Aes.IsSupported;
#endif
        }

        public void Dispose()
        {
        }
    }
}
