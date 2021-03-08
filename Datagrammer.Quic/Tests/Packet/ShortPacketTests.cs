using Datagrammer.Quic.Protocol;
using Datagrammer.Quic.Protocol.Packet;
using Datagrammer.Quic.Protocol.Packet.Frame;
using Datagrammer.Quic.Protocol.Tls;
using Xunit;

namespace Tests.Packet
{
    public class ShortPacketTests
    {
        [Fact]
        public void Write_Protected_ResultBytesAreExpected()
        {
            //Arrange
            var expectedBytes = GetProtectedMessageHex();
            var buffer = new byte[PacketBuffer.MaxPacketSize];
            var destConnectionId = PacketConnectionId.Empty;
            var packetNumbers = GetPacketNumbersHex();
            var currentPacketNumber = PacketNumber.Parse(Utils.ParseHexString(packetNumbers.Current));
            var largestPacketNumber = PacketNumber.Parse(Utils.ParseHexString(packetNumbers.Largest));
            var secrets = GetSecrets();
            var aead = Cipher.TLS_CHACHA20_POLY1305_SHA256.CreateAead(Utils.ParseHexString(secrets.Iv), Utils.ParseHexString(secrets.Key));
            var cipher = Cipher.TLS_CHACHA20_POLY1305_SHA256.CreateCipher(Utils.ParseHexString(secrets.Hp));

            //Act
            var cursor = new MemoryCursor(buffer);

            using (ShortPacket.StartProtectedWriting(aead, cipher, cursor, destConnectionId, currentPacketNumber, largestPacketNumber))
            {
                PingFrame.Write(cursor);
            }

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(cursor.PeekStart().ToArray()), true);
        }

        [Fact]
        public void Read_Protected_ResultBytesAreExpected()
        {
            //Arrange
            var messageBytes = Utils.ParseHexString(GetProtectedMessageHex());
            var destConnectionId = PacketConnectionId.Empty;
            var packetNumbers = GetPacketNumbersHex();
            var currentPacketNumber = PacketNumber.Parse(Utils.ParseHexString(packetNumbers.Current));
            var largestPacketNumber = PacketNumber.Parse(Utils.ParseHexString(packetNumbers.Largest));
            var secrets = GetSecrets();
            var aead = Cipher.TLS_CHACHA20_POLY1305_SHA256.CreateAead(Utils.ParseHexString(secrets.Iv), Utils.ParseHexString(secrets.Key));
            var cipher = Cipher.TLS_CHACHA20_POLY1305_SHA256.CreateCipher(Utils.ParseHexString(secrets.Hp));

            //Act
            var cursor = new MemoryCursor(messageBytes);

            var result = ShortPacket.TryParseProtectedByConnectionId(aead, cipher, cursor, destConnectionId, largestPacketNumber, out var packet);

            using (packet.Payload.SetCursor(cursor))
            {
                result &= PingFrame.TryParse(cursor);

                result &= cursor.IsEnd();
            }

            result &= cursor.IsEnd();

            //Assert
            Assert.True(result);
            Assert.Equal(destConnectionId, packet.DestinationConnectionId);
            Assert.Equal(currentPacketNumber, packet.Number);
        }

        private (string Key, string Iv, string Hp) GetSecrets()
        {
            return ("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8", "e0459b3474bdd0e44a41c144", "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
        }

        private (string Current, string Largest) GetPacketNumbersHex()
        {
            return ("2700bff4", "2700bec8");
        }

        private string GetProtectedMessageHex()
        {
            return "4cfe4189655e5cd55c41f69080575d7999c25a5bfb";
        }
    }
}
