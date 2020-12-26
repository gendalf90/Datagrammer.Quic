using Datagrammer.Quic.Protocol.Error;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct ServerHello
    {
        private ServerHello(HandshakeRandom random,
                            Cipher cipher,
                            SessionId sessionId,
                            MemoryBuffer payload)
        {
            Random = random;
            Cipher = cipher;
            SessionId = sessionId;
            Payload = payload;
        }

        public HandshakeRandom Random { get; }

        public Cipher Cipher { get; }

        public SessionId SessionId { get; }

        public MemoryBuffer Payload { get; }

        public static bool TryParse(MemoryCursor cursor, out ServerHello result)
        {
            result = new ServerHello();

            if (!HandshakeType.TrySlice(cursor, HandshakeType.ServerHello))
            {
                return false;
            }

            using (HandshakeLength.SliceBytes(cursor).SetCursor(cursor))
            {
                if (!ProtocolVersion.TrySlice(cursor, ProtocolVersion.Tls12))
                {
                    throw new EncodingException();
                }

                var random = HandshakeRandom.Parse(cursor);
                var sessionId = SessionId.Parse(cursor);
                var cipher = Cipher.Parse(cursor);

                if (!CompressionMethod.TrySliceEmptyValue(cursor))
                {
                    throw new EncodingException();
                }

                var payload = ByteVector.SliceVectorBytes(cursor, 0..ushort.MaxValue);

                if (cursor.HasNext())
                {
                    throw new EncodingException();
                }

                result = new ServerHello(random, cipher, sessionId, payload);

                return true;
            }
        }

        public static CursorHandshakeWritingContext StartWriting(MemoryCursor cursor,
                                                                 HandshakeRandom random,
                                                                 Cipher cipher,
                                                                 SessionId sessionId)
        {
            HandshakeType.ServerHello.WriteBytes(cursor);

            var payloadContext = HandshakeLength.StartWriting(cursor);

            ProtocolVersion.Tls12.WriteBytes(cursor);
            random.WriteBytes(cursor);
            sessionId.WriteBytes(cursor);
            cipher.WriteBytes(cursor);
            CompressionMethod.WriteEmptyValue(cursor);

            var extensionsContext = ByteVector.StartVectorWriting(cursor, 0..ushort.MaxValue);

            return new CursorHandshakeWritingContext(payloadContext, extensionsContext);
        }
    }
}
