import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;

public class Main {
    static class ULEB128 {
        public static int decode(byte[] bytes) {
            int result = 0;
            int shift = 0;
            int index = 0;
            byte currentByte;

            do {
                currentByte = bytes[index];
                result |= (currentByte & 0x7F) << shift;
                shift += 7;
                index++;
            } while ((currentByte & 0x80) != 0);

            return result;
        }

        public static byte[] encode(int value) {
            byte[] result = new byte[5];
            int index = 0;

            do {
                byte currentByte = (byte) (value & 0x7F);
                value >>= 7;
                if (value != 0) {
                    currentByte |= 0x80;
                }
                result[index] = currentByte;
                index++;
            } while (value != 0);

            byte[] encodedBytes = new byte[index];
            System.arraycopy(result, 0, encodedBytes, 0, index);

            return encodedBytes;
        }

        public static int calculateLength(byte[] bytes, int position) {
            int counter = position;

            while (bytes[position++] < 0) {
                counter += 1;
            }

            return counter;
        }
    }

    record Packet(byte length, byte[] payload, byte crc8) {
        public byte[] getRawByteArray() {
            return ByteBuffer.allocate(2 + payload.length)
                    .put(length)
                    .put(payload)
                    .put(crc8)
                    .array();
        }

        public static Packet fromBinary(byte[] binaryArray) {
            Packet result = null;
            byte length = binaryArray[0];
            byte[] rawPayload = Payload.fromBinary(Arrays.copyOfRange(binaryArray, 1, length + 1)).getRawByteArray();

            if (computeCRC8(rawPayload) == binaryArray[length + 1]) {
                result = new Packet(
                        length,
                        rawPayload,
                        binaryArray[length + 1]
                );
            }

            return result;
        }

        public static ArrayList<Packet> fetchRawPackets(byte[] rawPackets) {
            ArrayList<Packet> packets = new ArrayList<>();

            int packetIndex = 0;
            while (packetIndex < rawPackets.length) {
                Packet currentPacket = Packet.fromBinary(Arrays.copyOfRange(rawPackets, packetIndex, packetIndex + rawPackets[packetIndex] + 2));
                if (currentPacket != null) {
                    packets.add(currentPacket);
                }

                packetIndex += rawPackets[packetIndex] + 2;
            }

            return packets;
        }
    }

    public record Payload(byte[] src, byte[] dst, byte[] serial, byte devType, byte cmd, byte[] cmdBody) {
        public byte[] getRawByteArray() {
            return ByteBuffer.allocate(src.length + dst.length + serial.length + 2 + cmdBody.length)
                    .put(src)
                    .put(dst)
                    .put(serial)
                    .put(devType)
                    .put(cmd)
                    .put(cmdBody)
                    .array();
        }

        public static Payload fromBinary(byte[] binaryArray) {
            int endFirstArray = ULEB128.calculateLength(binaryArray, 0) + 1;
            int endSecondArray = ULEB128.calculateLength(binaryArray, endFirstArray) + 1;
            int endThirdArray = ULEB128.calculateLength(binaryArray, endSecondArray) + 1;

            return new Payload(
                    Arrays.copyOfRange(binaryArray, 0, endFirstArray),
                    Arrays.copyOfRange(binaryArray, endFirstArray, endSecondArray),
                    Arrays.copyOfRange(binaryArray, endSecondArray, endThirdArray),
                    binaryArray[endThirdArray],
                    binaryArray[endThirdArray + 1],
                    Arrays.copyOfRange(binaryArray, endThirdArray + 2, binaryArray.length)
            );
        }
    }

    enum DeviceType {
        SmartHub(0x01), EnvSensor(0x02), Switch(0x03), Lamp(0x04), Socket(0x05), Clock(0x06);

        private final int code;

        DeviceType(int code) {
            this.code = code;
        }

        public int getCode() {
            return code;
        }

        public static DeviceType fromCode(int deviceCode) {
            for (DeviceType deviceType : DeviceType.values()) {
                if (deviceType.getCode() == deviceCode) {
                    return deviceType;
                }
            }
            return null;
        }
    }

    enum CommandType {
        WHOISHERE(0x01), IAMHERE(0x02), GETSTATUS(0x03), STATUS(0x04), SETSTATUS(0x05), TICK(0x06);

        private final int code;

        CommandType(int code) {
            this.code = code;
        }

        public int getCode() {
            return code;
        }

        public static CommandType fromCode(int commandCode) {
            for (CommandType commandType : CommandType.values()) {
                if (commandType.getCode() == commandCode) {
                    return commandType;
                }
            }
            return null;
        }
    }

    record Device(String devName, byte[] devProps) {
    }

    record TimerCommandBody(byte[] timestamp) {
    }

    record EnvSensorProps(byte sensors, Trigger[] triggers) {
    }

    record Trigger(byte op, byte[] value, String name) {
    }

    record EnvSensorStatusCmdBody(byte[][] values) {
    }

    static class Switch {
        private String[] devProps;

        public Switch(String[] devProps) {
            this.devProps = devProps;
        }

        public String[] getDevProps() {
            return devProps;
        }

        public void setDevProps(String[] devProps) {
            this.devProps = devProps;
        }
    }

    public class Lamp {
        // Lamp class implementation here
    }

    private static final String HUB_NAME = "HUB01";
    private static URL SERVER_URL;
    private static int DeviceAddress;
    private static int SerialNumber = 1;
    private static int LampID = -1;
    private static final List<Packet> Packets = new ArrayList<>();

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java HomeHub <url> <deviceAddress>");
            return;
        }

        try {
            URI uri = new URI(args[0]);
            SERVER_URL = uri.toURL();
            DeviceAddress = Integer.parseInt(args[1], 16);

            Packet mainPacket = formBroadcastPacket(CommandType.WHOISHERE, convertStringToByteArray(HUB_NAME));
            String encodedMainPacket = encodePacket(mainPacket);

            while (true) {
                int responseCode = sendPostRequest(SERVER_URL, encodedMainPacket, true);

                if (responseCode == 200) {
                    while (!Packets.isEmpty()) {
                        Packet currentPacket = Packets.get(0);

                        processData(currentPacket);

                        Packets.remove(currentPacket);
                    }
                } else if (responseCode == 204) {
                    System.exit(0);
                } else {
                    System.exit(99);
                }

                Thread.sleep(1000);
            }
        } catch (IOException | URISyntaxException | InterruptedException e) {
            System.out.println("Exception generated: " + e);
            System.exit(99);
        }
    }

    private static Packet formPacket(byte[] destinationId, DeviceType deviceType, CommandType commandType, byte[] commandBody) {
        byte[] payloadByteArray = new Payload(
                ULEB128.encode(DeviceAddress),
                destinationId,
                ULEB128.encode(SerialNumber++),
                (byte) deviceType.code,
                (byte) commandType.code,
                commandBody
        ).getRawByteArray();

        return new Packet((byte) payloadByteArray.length, payloadByteArray, computeCRC8(payloadByteArray));
    }

    private static Packet formBroadcastPacket(CommandType commandType, byte[] commandBody) {
        byte[] payloadByteArray = new Payload(
                ULEB128.encode(DeviceAddress),
                ULEB128.encode(16383),
                ULEB128.encode(SerialNumber++),
                (byte) DeviceType.SmartHub.code,
                (byte) commandType.code,
                commandBody
        ).getRawByteArray();

        return new Packet((byte) payloadByteArray.length, payloadByteArray, computeCRC8(payloadByteArray));
    }

    private static String encodePacket(Packet packet) throws IOException {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(packet.getRawByteArray());
    }

    private static int sendPostRequest(URL serverUrl, String encodedData, boolean isAdding) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) serverUrl.openConnection();

        // Настройка соединения
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);

        // Установка заголовков запроса
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setRequestProperty("Content-Length", String.valueOf(encodedData.length()));

        // Отправка данных
        connection.getOutputStream().write(encodedData.getBytes());

        // Получение кода ответа
        int responseCode = connection.getResponseCode();
        if (isAdding) {
            String responseData = new String(connection.getInputStream().readAllBytes());
            Packets.addAll(Packet.fetchRawPackets(Base64.getUrlDecoder().decode(responseData)));
        }

        // Закрытие соединения
        connection.disconnect();

        return responseCode;
    }

    private static void processData(Packet packet) throws IOException, URISyntaxException {
        Payload currentPacketPayload = Payload.fromBinary(packet.payload);

        switch (Objects.requireNonNull(DeviceType.fromCode(currentPacketPayload.devType))) {
            case SmartHub, EnvSensor, Socket, Clock -> {
            }
            case Switch -> {
                if (Objects.requireNonNull(CommandType.fromCode(currentPacketPayload.cmd)) == CommandType.STATUS && LampID != -1) {
                    Packet requestPacket = formPacket(ULEB128.encode(LampID), DeviceType.Lamp, CommandType.SETSTATUS, currentPacketPayload.cmdBody);
                    sendPostRequest(SERVER_URL, encodePacket(requestPacket), false);
                }
                else {
                    Packet requestPacket = formPacket(currentPacketPayload.src, DeviceType.Switch, CommandType.GETSTATUS, new byte[] {});
                    sendPostRequest(SERVER_URL, encodePacket(requestPacket), false);
                }
            }
            case Lamp -> {
                LampID = ULEB128.decode(currentPacketPayload.src);
            }
        }
    }

    private static byte[] convertStringToByteArray(String input) {
        byte[] bytes = input.getBytes();
        byte[] result = new byte[bytes.length + 1];

        result[0] = (byte) bytes.length;
        System.arraycopy(bytes, 0, result, 1, bytes.length);

        return result;
    }

    private static byte computeCRC8(byte[] bytes) {
        final byte generator = 0x1D;
        byte crc = 0;

        for (byte currByte : bytes) {
            crc ^= currByte;

            for (int i = 0; i < 8; i++) {
                if ((crc & 0x80) != 0) {
                    crc = (byte) ((crc << 1) ^ generator);
                } else {
                    crc <<= 1;
                }
            }
        }

        return crc;
    }
}