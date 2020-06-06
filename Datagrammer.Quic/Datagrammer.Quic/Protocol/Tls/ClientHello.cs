using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct ClientHello
    {
        public ClientHello(HandshakeRandom random,
                           CipherSuite cipherSuite,
                           SessionId sessionId,
                           ReadOnlyMemory<byte> payload)
        {
            Random = random;
            CipherSuite = cipherSuite;
            SessionId = sessionId;
            Payload = payload;
        }

        public HandshakeRandom Random { get; }

        public CipherSuite CipherSuite { get; }

        public SessionId SessionId { get; }

        public ReadOnlyMemory<byte> Payload { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out ClientHello result, out ReadOnlyMemory<byte> remainings)
        {
            result = new ClientHello();
            remainings = bytes;

            if (bytes.IsEmpty)
            {
                return false;
            }

            var type = HandshakeType.Parse(bytes, out var afterTypeBytes);

            if(type != HandshakeType.ClientHello)
            {
                return false;
            }

            var body = HandshakeLength.SliceHandshakeBytes(afterTypeBytes, out var afterBodyBytes);
            var legacyVersion = ProtocolVersion.Parse(body, out var afterLegacyVersionBytes);

            if(legacyVersion != ProtocolVersion.Tls12)
            {
                throw new EncodingException();
            }

            var random = HandshakeRandom.Parse(afterLegacyVersionBytes, out var afterRandomBytes);
            var sessionId = SessionId.Parse(afterRandomBytes, out var afterSessionIdBytes);
            var cipherSuite = CipherSuite.Parse(afterSessionIdBytes, out var afterCipherSuiteBytes);

            if(!CompressionMethod.CheckForEmpty(afterCipherSuiteBytes, out var afterCompressionMethodBytes))
            {
                throw new EncodingException();
            }

            var extensionBytes = ByteVector.SliceVectorBytes(afterCompressionMethodBytes, 8..ushort.MaxValue, out var afterExtensionBytes);

            if(!afterExtensionBytes.IsEmpty)
            {
                throw new EncodingException();
            }

            result = new ClientHello(random, cipherSuite, sessionId, extensionBytes);
            remainings = afterBodyBytes;

            return true;
        }
    }
}
