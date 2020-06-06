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

        public bool HasVersion(ProtocolVersion version)
        {
            var remainings = bytes;

            while (!remainings.IsEmpty)
            {
                if (ProtocolVersion.Parse(remainings, out remainings) == version)
                {
                    return true;
                }
            }

            return false;
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

        public static int WriteWithVersion(Span<byte> destination, ProtocolVersion version)
        {
            ExtensionType.SupportedVersions.WriteBytes(destination, out var afterTypeBytes);

            var context = ExtensionVectorPayload.StartWriting(afterTypeBytes);

            context.Move(version.WriteBytes(context.Remainings));

            return ExtensionVectorPayload.FinishWriting(context, 2..254);
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
