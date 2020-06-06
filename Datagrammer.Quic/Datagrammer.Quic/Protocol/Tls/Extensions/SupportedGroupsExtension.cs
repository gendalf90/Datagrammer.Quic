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

        public bool HasGroup(NamedGroup group)
        {
            var remainings = bytes;

            while (!remainings.IsEmpty)
            {
                if (NamedGroup.Parse(remainings, out remainings) == group)
                {
                    return true;
                }
            }

            return false;
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

            var payload = ExtensionVectorPayload.Slice(afterTypeBytes, 0..ushort.MaxValue, out remainings);

            result = new SupportedGroupsExtension(payload);

            return true;
        }

        public static int WriteWithGroup(Span<byte> destination, NamedGroup group)
        {
            ExtensionType.SignatureAlgorithms.WriteBytes(destination, out var afterTypeBytes);

            var context = ExtensionVectorPayload.StartWriting(afterTypeBytes);

            context.Move(group.WriteBytes(context.Remainings));

            return ExtensionVectorPayload.FinishWriting(context, 0..ushort.MaxValue);
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
