﻿using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct PskKeyExchangeModesExtension
    {
        //private const byte PskKeMode = 0;
        private static readonly byte[] PskDheKeMode = { 1 };

        private readonly ReadOnlyMemory<byte> bytes;

        private PskKeyExchangeModesExtension(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out PskKeyExchangeModesExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new PskKeyExchangeModesExtension();
            remainings = bytes;

            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if (type != ExtensionType.PskKeyExchangeModes)
            {
                return false;
            }

            var payload = ExtensionVectorPayload.Slice(afterTypeBytes, 1..255, out remainings);

            result = new PskKeyExchangeModesExtension(payload);

            return true;
        }

        public static PskKeyExchangeModesExtension PskDheKe { get; } = new PskKeyExchangeModesExtension(PskDheKeMode);

        public void WriteBytes(ref Span<byte> destination)
        {
            ExtensionType.PskKeyExchangeModes.WriteBytes(ref destination);

            var context = ExtensionVectorPayload.StartWriting(ref destination, 1..255);

            if (!bytes.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(bytes.Length);

            context.Complete(ref destination);
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}