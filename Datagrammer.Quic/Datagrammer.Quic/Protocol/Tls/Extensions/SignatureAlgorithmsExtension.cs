using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct SignatureAlgorithmsExtension
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private SignatureAlgorithmsExtension(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public bool HasScheme(SignatureScheme scheme)
        {
            var remainings = bytes;

            while (!remainings.IsEmpty)
            {
                if (SignatureScheme.Parse(remainings, out remainings) == scheme)
                {
                    return true;
                }
            }

            return false;
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out SignatureAlgorithmsExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new SignatureAlgorithmsExtension();
            remainings = bytes;

            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if (type != ExtensionType.SignatureAlgorithms)
            {
                return false;
            }

            var payload = ExtensionVectorPayload.Slice(afterTypeBytes, 0..ushort.MaxValue, out remainings);

            result = new SignatureAlgorithmsExtension(payload);

            return true;
        }

        public static int WriteWithScheme(Span<byte> destination, SignatureScheme signatureScheme)
        {
            ExtensionType.SignatureAlgorithms.WriteBytes(destination, out var afterTypeBytes);

            var context = ExtensionVectorPayload.StartWriting(afterTypeBytes);

            context.Move(signatureScheme.WriteBytes(context.Remainings));

            return ExtensionVectorPayload.FinishWriting(context, 0..ushort.MaxValue);
        }
    }
}
