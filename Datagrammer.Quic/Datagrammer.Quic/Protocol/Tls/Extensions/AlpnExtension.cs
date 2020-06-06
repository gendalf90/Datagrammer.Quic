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

            var payload = ExtensionVectorPayload.Slice(afterTypeBytes, 2..ushort.MaxValue, out remainings);

            result = new AlpnExtension(payload);

            return true;
        }

        public static int WriteWithProtocolName(Span<byte> destination, ProtocolName protocolName)
        {
            ExtensionType.ApplicationLayerProtocolNegotiation.WriteBytes(destination, out var afterTypeBytes);

            var context = ExtensionVectorPayload.StartWriting(afterTypeBytes);

            context.Move(protocolName.WriteBytes(context.Remainings));

            return ExtensionVectorPayload.FinishWriting(context, 2..ushort.MaxValue);
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
