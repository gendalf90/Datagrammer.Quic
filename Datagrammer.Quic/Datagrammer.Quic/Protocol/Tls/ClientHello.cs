using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct ClientHello
    {
        private ClientHello(HandshakeRandom random,
                            CipherSuite cipherSuite,
                            SessionId sessionId,
                            MemoryBuffer payload)
        {
            Random = random;
            CipherSuite = cipherSuite;
            SessionId = sessionId;
            Payload = payload;
        }

        public HandshakeRandom Random { get; }

        public CipherSuite CipherSuite { get; }

        public SessionId SessionId { get; }

        public MemoryBuffer Payload { get; }

        public static bool TryParse(MemoryCursor cursor, out ClientHello result)
        {
            result = new ClientHello();

            if (!HandshakeType.TrySlice(cursor, HandshakeType.ClientHello))
            {
                return false;
            }

            using (HandshakeLength.SliceBytes(cursor).SetCursor(cursor))
            {
                if(!ProtocolVersion.TrySlice(cursor, ProtocolVersion.Tls12))
                {
                    throw new EncodingException();
                }

                var random = HandshakeRandom.Parse(cursor);
                var sessionId = SessionId.Parse(cursor);
                var cipherSuite = CipherSuite.Parse(cursor);

                if (!CompressionMethod.TrySliceEmptyList(cursor))
                {
                    throw new EncodingException();
                }

                var payload = ByteVector.SliceVectorBytes(cursor, 0..ushort.MaxValue);

                if(cursor.HasNext())
                {
                    throw new EncodingException();
                }

                result = new ClientHello(random, cipherSuite, sessionId, payload);

                return true;
            }
        }

        public static CursorHandshakeWritingContext StartWriting(MemoryCursor cursor,
                                                                 HandshakeRandom random,
                                                                 ReadOnlyMemory<Cipher> ciphers,
                                                                 SessionId sessionId)
        {
            HandshakeType.ClientHello.WriteBytes(cursor);

            var payloadContext = HandshakeLength.StartWriting(cursor);

            ProtocolVersion.Tls12.WriteBytes(cursor);
            random.WriteBytes(cursor);
            sessionId.WriteBytes(cursor);
            CipherSuite.Write(cursor, ciphers);
            CompressionMethod.WriteEmptyList(cursor);

            var extensionsContext = ByteVector.StartVectorWriting(cursor, 0..ushort.MaxValue);

            return new CursorHandshakeWritingContext(payloadContext, extensionsContext);
        }
    }
}
