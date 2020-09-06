using Datagrammer.Quic.Protocol.Error;
using System;
using System.Collections.Generic;
using System.IO;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct SupportedVersionExtension
    {
        private readonly ReadOnlyMemory<byte> bytes;
        private readonly bool isList;

        private SupportedVersionExtension(ReadOnlyMemory<byte> bytes, bool isList)
        {
            this.bytes = bytes;
            this.isList = isList;
        }

        public static bool TryParseList(ReadOnlyMemory<byte> bytes, out SupportedVersionExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new SupportedVersionExtension();
            remainings = bytes;

            if (ExtensionType.Parse(bytes, out var afterTypeBytes) != ExtensionType.SupportedVersions)
            {
                return false;
            }

            var payload = ExtensionVectorPayload.Slice(afterTypeBytes, 2..254, out remainings);

            result = new SupportedVersionExtension(payload, true);

            return true;
        }

        public static bool TryParseSingle(ReadOnlyMemory<byte> bytes, out SupportedVersionExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new SupportedVersionExtension();
            remainings = bytes;

            if (ExtensionType.Parse(bytes, out var afterTypeBytes) != ExtensionType.SupportedVersions)
            {
                return false;
            }

            var payload = ExtensionPayload.Slice(afterTypeBytes, out remainings);

            result = new SupportedVersionExtension(payload, false);

            return true;
        }

        public static SupportedVersionExtension CreateFromList(IEnumerable<ProtocolVersion> versions)
        {
            using (var stream = new MemoryStream())
            {
                foreach (var version in versions)
                {
                    version.WriteBytes(stream);
                }

                return new SupportedVersionExtension(stream.ToArray(), true);
            }
        }

        public void Write(ref Span<byte> destination)
        {
            ExtensionType.SupportedVersions.WriteBytes(ref destination);

            var context = ExtensionPayload.StartWriting(ref destination);

            if (isList)
            {
                WriteVector(ref destination);
            }
            else
            {
                WriteBytes(ref destination);
            }

            context.Complete(ref destination);
        }

        private void WriteBytes(ref Span<byte> destination)
        {
            if (!bytes.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(bytes.Length);
        }

        private void WriteVector(ref Span<byte> destination)
        {
            var vectorContext = ByteVector.StartVectorWriting(ref destination, 2..254);

            WriteBytes(ref destination);

            vectorContext.Complete(ref destination);
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
