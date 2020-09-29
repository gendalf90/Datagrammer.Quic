using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct ApplicationData
    {
        private ApplicationData(ReadOnlyMemory<byte> payload)
        {
            Payload = payload;
        }

        public ReadOnlyMemory<byte> Payload { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out ApplicationData result, out ReadOnlyMemory<byte> remainings)
        {
            result = new ApplicationData();
            remainings = bytes;

            if (bytes.IsEmpty)
            {
                return false;
            }

            var type = ApplicationType.Parse(bytes, out var afterTypeBytes);

            if (type != ApplicationType.ApplicationData)
            {
                return false;
            }

            var legacyVersion = ProtocolVersion.Parse(afterTypeBytes, out var afterLegacyVersionBytes);

            if (legacyVersion != ProtocolVersion.Tls12)
            {
                throw new EncodingException();
            }
            
            var body = ApplicationLength.SliceApplicationBytes(afterLegacyVersionBytes, out remainings);

            result = new ApplicationData(body);

            return true;
        }

        public static ApplicationDataWritingContext StartWriting(ref Span<byte> destination)
        {
            ApplicationType.ApplicationData.WriteBytes(ref destination);
            ProtocolVersion.Tls12.WriteBytes(ref destination);

            var payloadContext = ApplicationLength.StartWriting(ref destination);

            return new ApplicationDataWritingContext(payloadContext);
        }
    }
}
