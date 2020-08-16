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

            var payload = ExtensionPayload.Slice(afterTypeBytes, out remainings);

            result = new SupportedVersionExtension(payload);

            return true;
        }

        public bool HasSelectedSupportedVersion()
        {
            var version = ProtocolVersion.Parse(bytes, out var remainings);

            if(!remainings.IsEmpty)
            {
                throw new EncodingException();
            }

            return version == ProtocolVersion.Tls13;
        }

        public bool TrySelectOneSupportedFromList(out SupportedVersionExtension result)
        {
            var versionList = ByteVector.SliceVectorBytes(bytes, 2..254, out var remainings);
            
            result = new SupportedVersionExtension();

            if(!remainings.IsEmpty)
            {
                throw new EncodingException();
            }

            while(!versionList.IsEmpty)
            {
                if(TryParseSupportedVersion(versionList, out result, out versionList))
                {
                    return true;
                }
            }

            return false;
        }

        private bool TryParseSupportedVersion(ReadOnlyMemory<byte> data, out SupportedVersionExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new SupportedVersionExtension();

            if(ProtocolVersion.Parse(data, out remainings) != ProtocolVersion.Tls13)
            {
                return false;
            }

            result = new SupportedVersionExtension(data.Slice(0, data.Length - remainings.Length));

            return true;
        }

        public static void WriteSupportedList(ref Span<byte> destination)
        {
            ExtensionType.SupportedVersions.WriteBytes(ref destination);

            var context = ExtensionVectorPayload.StartWriting(ref destination, 2..254);

            ProtocolVersion.Tls13.WriteBytes(ref destination);

            context.Complete(ref destination);
        }

        public void WriteBytes(ref Span<byte> destination)
        {
            ExtensionType.SupportedVersions.WriteBytes(ref destination);

            var context = ExtensionPayload.StartWriting(ref destination);

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
