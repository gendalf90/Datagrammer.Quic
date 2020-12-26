using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct AlpnExtension
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private AlpnExtension(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out AlpnExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new AlpnExtension();
            remainings = bytes;

            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if (type != ExtensionType.ApplicationLayerProtocolNegotiation)
            {
                return false;
            }

            var payload = ExtensionVectorLength.Slice(afterTypeBytes, 2..ushort.MaxValue, out remainings);

            result = new AlpnExtension(payload);

            return true;
        }

        public void WriteBytes(ref Span<byte> destination)
        {
            ExtensionType.ApplicationLayerProtocolNegotiation.WriteBytes(ref destination);

            var context = ExtensionVectorLength.StartWriting(ref destination, 2..ushort.MaxValue);

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
