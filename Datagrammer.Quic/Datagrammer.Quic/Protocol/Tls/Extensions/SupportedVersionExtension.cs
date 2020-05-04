using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct SupportedVersionExtension
    {
        private SupportedVersionExtension(bool isTls13Supported)
        {
            IsTls13Supported = isTls13Supported;
        }

        public bool IsTls13Supported { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out SupportedVersionExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new SupportedVersionExtension();
            remainings = bytes;

            if (bytes.IsEmpty)
            {
                return false;
            }

            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if (type != ExtensionType.SupportedVersions)
            {
                return false;
            }

            var payload = ExtensionLength.SlicePayload(afterTypeBytes, out var afterPayloadBytes);
            var versionBytes = ByteVector.SliceVectorBytes(payload, 0..254, out var afterVersionBytes);

            if(!afterVersionBytes.IsEmpty)
            {
                throw new EncodingException();
            }

            var isTls13Supported = HasTls13Version(versionBytes);

            remainings = afterPayloadBytes;
            result = new SupportedVersionExtension(isTls13Supported);

            return true;
        }

        public static SupportedVersionExtension Tls13OnlySupported { get; } = new SupportedVersionExtension(true);

        public int WriteBytes(Span<byte> bytes)
        {
            ExtensionType.SupportedVersions.WriteBytes(bytes, out bytes);

            var payloadContext = ExtensionLength.StartPayloadWriting(bytes);
            var versionContext = ByteVector.StartVectorWriting(payloadContext.Current);

            if(IsTls13Supported)
            {
                versionContext.Move(ProtocolVersion.Tls13.WriteBytes(versionContext.Current));
            }
            
            payloadContext.Move(ByteVector.FinishVectorWriting(versionContext, 0..254));
            
            return ExtensionLength.FinishPayloadWriting(payloadContext);
        }

        private static bool HasTls13Version(ReadOnlyMemory<byte> bytes)
        {
            var remainings = bytes;

            while(!remainings.IsEmpty)
            {
                if(ProtocolVersion.Parse(remainings, out remainings) == ProtocolVersion.Tls13)
                {
                    return true;
                }
            }

            return false;
        }
    }
}
