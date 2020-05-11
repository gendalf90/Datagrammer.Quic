using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct PskKeyExchangeModesExtension
    {
        private const byte PskKeMode = 0;
        private const byte PskDheKeMode = 1;

        private readonly ReadOnlyMemory<byte> bytes;

        private PskKeyExchangeModesExtension(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public bool HasPskKeMode()
        {
            foreach(var b in bytes.Span)
            {
                if (b == PskKeMode)
                {
                    return true;
                }
            }

            return false;
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

        public static int WriteWithPskKeMode(Span<byte> destination)
        {
            ExtensionType.SupportedVersions.WriteBytes(destination, out var afterTypeBytes);

            var context = ExtensionVectorPayload.StartWriting(afterTypeBytes);

            context.Remainings[0] = PskKeMode;
            context.Move(1);

            return ExtensionVectorPayload.FinishWriting(context, 1..255);
        }
    }
}
