using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct SupportedVersionExtension
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private SupportedVersionExtension(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out SupportedVersionExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new SupportedVersionExtension();
            remainings = bytes;

            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if (type != ExtensionType.SupportedVersions)
            {
                return false;
            }

            var payload = ExtensionVectorPayload.Slice(afterTypeBytes, 2..254, out remainings);

            result = new SupportedVersionExtension(payload);

            return true;
        }

        public void WriteBytes(ref Span<byte> destination)
        {
            ExtensionType.SupportedVersions.WriteBytes(ref destination);

            var context = ExtensionVectorPayload.StartWriting(ref destination, 2..254);

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
