using Datagrammer.Quic.Protocol.Error;
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

        public void WriteBytes(ref Span<byte> destination)
        {
            ExtensionType.KeyShare.WriteBytes(ref destination);

            var context = ExtensionVectorPayload.StartWriting(ref destination, 0..ushort.MaxValue);

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
