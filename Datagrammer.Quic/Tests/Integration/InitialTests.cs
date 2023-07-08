using Datagrammer.Quic.Protocol;
using Datagrammer.Quic.Protocol.Packet;
using Datagrammer.Quic.Protocol.Packet.Frame;
using Datagrammer.Quic.Protocol.Tls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Tests.Integration
{
    public class InitialTests
    {
        [Fact]
        public void SendInitial_CorrectResponseFromServer()
        {
            //Arrang
            var sourceConnectionId = PacketConnectionId.Generate();
            var destConnectionId = PacketConnectionId.Generate();
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var secrets = destConnectionId.CreateClientInitialSecrets(hash);
            var aead = Cipher.TLS_AES_128_GCM_SHA256.CreateAead(secrets.Iv.ToArray(), secrets.Key.ToArray()));
            var cipher = Cipher.TLS_AES_128_GCM_SHA256.CreateCipher(secrets.Hp.ToArray());
            var buffer = new byte[PacketBuffer.MaxPacketSize];
            var cursor = new MemoryCursor(buffer);
            var version = PacketVersion.Current;
            var packetNumber = PacketNumber.Initial;
            var packetToken = PacketToken.Empty;
            var handshakeRandom = HandshakeRandom.Generate();
            var ciphers = Cipher.Supported;
            var sessionId = SessionId.Empty;

            //Act
            using (InitialPacket.StartProtectedWriting(aead, cipher, cursor, version, destConnectionId, sourceConnectionId, packetNumber, packetToken))
            {
                using (PaddingFrame.EnsureLength(cursor, PacketBuffer.MinPacketSize))
                {
                    using (CryptoFrame.StartWriting(cursor, 0))
                    {
                        using (ClientHello.StartWriting(cursor, handshakeRandom, ciphers, sessionId))
                        {

                        }
                    }
                }
            }

            //Assert


        }
    }
}
