using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct SupportedGroupsExtension
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private SupportedGroupsExtension(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out SupportedGroupsExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new SupportedGroupsExtension();
            remainings = bytes;

            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if (type != ExtensionType.SupportedGroups)
            {
                return false;
            }

            var payload = ExtensionVectorPayload.Slice(afterTypeBytes, 2..ushort.MaxValue, out remainings);

            result = new SupportedGroupsExtension(payload);

            return true;
        }

        public void WriteBytes(ref Span<byte> destination)
        {
            ExtensionType.SupportedGroups.WriteBytes(ref destination);

            var context = ExtensionVectorPayload.StartWriting(ref destination, 2..ushort.MaxValue);

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
