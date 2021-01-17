﻿using System;
using System.Security.Cryptography;

namespace Datagrammer.Quic.Protocol.Tls.Ciphers
{
    public class Aes128EcbCipher : ICipher
    {
        private const int MaskLength = 5;

        private readonly AesManaged aesAlgorithm;
        private readonly ICryptoTransform encryptor;
        private readonly ICryptoTransform decryptor;

        public Aes128EcbCipher(ReadOnlyMemory<byte> key)
        {
            aesAlgorithm = new AesManaged
            {
                KeySize = 128,
                Key = key.ToArray(),
                BlockSize = 128,
                Mode = CipherMode.ECB
            };
            encryptor = aesAlgorithm.CreateEncryptor();
            decryptor = aesAlgorithm.CreateDecryptor();
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

            var buffer = new byte[sample.Length];

            sample.CopyTo(buffer);

            encryptor.TransformBlock(buffer, 0, buffer.Length, buffer, 0);

            buffer
                .AsSpan()
                .Slice(0, MaskLength)
                .CopyTo(destination);

            return MaskLength;
        }

        public void Dispose()
        {
            encryptor.Dispose();
            decryptor.Dispose();
            aesAlgorithm.Dispose();
        }
    }
}
