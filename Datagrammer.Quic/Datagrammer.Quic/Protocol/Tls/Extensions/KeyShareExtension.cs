using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct KeyShareExtension
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private KeyShareExtension(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public bool TryGetByGroup(NamedGroup group, out KeyExchange keyExchange)
        {
            var remainings = bytes;

            keyExchange = new KeyExchange();

            while (!remainings.IsEmpty)
            {
                if (ParseEntry(remainings, out keyExchange, out remainings) == group)
                {
                    return true;
                }
            }

            return false;
        }

        private NamedGroup ParseEntry(ReadOnlyMemory<byte> bytes, out KeyExchange keyExchange, out ReadOnlyMemory<byte> remainings)
        {
            var group = NamedGroup.Parse(bytes, out var afterGroupBytes);

            keyExchange = KeyExchange.Parse(afterGroupBytes, out remainings);

            return group;
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out KeyShareExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new KeyShareExtension();
            remainings = bytes;

            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if (type != ExtensionType.KeyShare)
            {
                return false;
            }

            var payload = ExtensionVectorPayload.Slice(afterTypeBytes, 0..ushort.MaxValue, out remainings);

            result = new KeyShareExtension(payload);

            return true;
        }


        public static int WriteWithGroupAndKey(Span<byte> destination, NamedGroup group, KeyExchange keyExchange)
        {
            ExtensionType.KeyShare.WriteBytes(destination, out var afterTypeBytes);

            var context = ExtensionVectorPayload.StartWriting(afterTypeBytes);

            context.Move(group.WriteBytes(context.Remainings));
            context.Move(keyExchange.WriteBytes(context.Remainings));

            return ExtensionVectorPayload.FinishWriting(context, 0..ushort.MaxValue);
        }
    }
}
