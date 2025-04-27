package net.niese.java.steganography;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.zip.CRC32;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * A steganography tool for embedding and extracting files in PNG images.
 * Supports AES encryption, GZIP compression, and CRC32 integrity checks.
 */
public class Steganography {
    // Constants
    private static final byte[] MAGIC_STEG = {(byte) 0xED, (byte) 0xD1, (byte) 0xE0, (byte) 0x54}; // Base magic, LSB of 4th byte set dynamically
    private static final int MAX_FILENAME_LENGTH = 255;
    private static final int MAX_FILES = 255;

    // Fixed salt for encryption
    private static final byte[] SALT = new byte[] {
        (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
        (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
        (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
        (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F
    };

    /**
     * Configuration for steganography operations.
     */
    static class SteganographyConfig {
        Map<Integer, String> passwords = new HashMap<>();
        Set<String> noCompressionFiles = new HashSet<>();
        boolean skipCorrupted;
        boolean silentExtract;
        boolean silentDecrypt;
        boolean noCRC;
        int bitsPerPixel = 6; // Default to 6 bits per pixel
    }

    /**
     * Represents an embedded file's metadata and data.
     */
    static class FileData {
        String filename;
        byte[] data;
        byte[] embeddedData;
        int crc;
        boolean isCompressed;
        boolean isEncrypted;
        int embeddedSize;

        FileData(String filename, byte[] data, int crc, boolean isCompressed, boolean isEncrypted, int embeddedSize, byte[] embeddedData) {
            this.filename = filename;
            this.data = data;
            this.embeddedData = embeddedData;
            this.crc = crc;
            this.isCompressed = isCompressed;
            this.isEncrypted = isEncrypted;
            this.embeddedSize = embeddedSize;
        }

        // Optimization: Clear data to reduce memory usage
        void clearData() {
            if (data != null) {
                Arrays.fill(data, (byte) 0);
                data = null;
            }
        }
    }

    /**
     * Manages image data for steganography.
     */
    static class ImageContext {
        BufferedImage image;
        int width;
        int height;
        int maxBits;
        int bitsPerPixel;

        ImageContext(String imagePath) throws IOException {
            image = ImageIO.read(new File(imagePath));
            if (image == null) {
                throw new IOException("Failed to read image: " + imagePath);
            }
            width = image.getWidth();
            height = image.getHeight();
            maxBits = 0; // Set after bitsPerPixel is determined
        }

        void updateMaxBits() {
            maxBits = width * height * bitsPerPixel;
        }
    }

    /**
     * Validates the magic header and sets bitsPerPixel in ImageContext.
     */
    private static void validateMagicHeader(ImageContext ctx) throws Exception {
        // Restored: Try both 6 and 3 bits to ensure robustness
        byte[] extractedMagic6 = new byte[4];
        byte[] extractedMagic3 = new byte[4];
        ctx.bitsPerPixel = 6;
        extractBits(ctx, extractedMagic6, 0, 32);
        ctx.bitsPerPixel = 3;
        extractBits(ctx, extractedMagic3, 0, 32);

        byte[] extractedMagic = null;
        if (isValidMagic(extractedMagic6)) {
            extractedMagic = extractedMagic6;
            ctx.bitsPerPixel = (extractedMagic6[3] & 0x01) == 1 ? 6 : 3;
        } else if (isValidMagic(extractedMagic3)) {
            extractedMagic = extractedMagic3;
            ctx.bitsPerPixel = (extractedMagic3[3] & 0x01) == 1 ? 6 : 3;
        } else {
            throw new IllegalStateException("Image is not formatted. Please run 'format' first.");
        }

        ctx.updateMaxBits();
    }

    /**
     * Checks if the extracted magic header is valid.
     */
    private static boolean isValidMagic(byte[] extractedMagic) {
        for (int i = 0; i < 3; i++) {
            if (extractedMagic[i] != MAGIC_STEG[i]) {
                return false;
            }
        }
        return (extractedMagic[3] & 0xFE) == (MAGIC_STEG[3] & 0xFE);
    }

    /**
     * Formats an image for steganography use.
     */
    public static void formatData(String inputImagePath, String outputImagePath, SteganographyConfig config) throws Exception {
        Utils.validateImagePaths(inputImagePath, outputImagePath);
        ImageContext ctx = new ImageContext(inputImagePath);
        ctx.bitsPerPixel = config.bitsPerPixel;
        ctx.updateMaxBits();

        byte[] magicHeader = Arrays.copyOf(MAGIC_STEG, 4);
        magicHeader[3] |= (ctx.bitsPerPixel == 6 ? 1 : 0); // Set LSB of 4th byte
        byte[] data = new byte[5];
        System.arraycopy(magicHeader, 0, data, 0, 4);
        data[4] = 0; // Number of files = 0

        ImageProcessor.embedBits(ctx.image, ctx.width, ctx.height, data, true, 0, ctx.bitsPerPixel);
        if (!ImageIO.write(ctx.image, "png", new File(outputImagePath))) {
            throw new IOException("Failed to write image to " + outputImagePath);
        }
        System.out.println("Image formatted with " + ctx.bitsPerPixel + " bits per pixel. New image saved to " + outputImagePath);
    }

    /**
     * Lists embedded file details, using passwords for decryption.
     */
    public static void listData(String inputImagePath, SteganographyConfig config) throws Exception {
        ImageContext ctx = new ImageContext(inputImagePath);
        validateMagicHeader(ctx);

        config.silentDecrypt = false;
        config.skipCorrupted = true;
        config.bitsPerPixel = ctx.bitsPerPixel;
        ExtractResult extractResult = extractFilesFromImage(ctx, config, true, false, true, null);
        List<FileData> files = extractResult.files;
        int numFiles = files.size();
        int totalBitsUsed = 40; // Magic header + numFiles

        if (numFiles == 0) {
            System.out.println("Number of embedded files: 0");
        } else {
            System.out.println("Number of embedded files: " + numFiles);
            String crcHeaderFormat = config.noCRC ? "%3s" : "%12s";
            System.out.printf("\n%3s " + crcHeaderFormat + " %8s %1s %1s %9s %s\n",
                    "Num", "CRC", "Emb.size", "C", "P", "Filesize", "Filename");
            for (int fileIdx = 1; fileIdx <= numFiles; fileIdx++) {
                FileData file = files.get(fileIdx - 1);
                totalBitsUsed += (1 + file.filename.length() + 1 + 4 + 4 + file.embeddedSize) * 8;
                String crcStatus = DataProcessor.calculateCRC(file.embeddedData) == file.crc ? "OK" : "ERR";
                String crcDisplay = config.noCRC ? crcStatus : String.format("%08X %s", file.crc, crcStatus);
                String fileSize = (file.data.length == 0 && file.isEncrypted) ? "<unknown>" : String.valueOf(file.data.length);
                System.out.printf("%3d " + crcHeaderFormat + " %8d %1s %1s %9s %s\n",
                        fileIdx, crcDisplay, file.embeddedSize,
                        file.isCompressed ? "Y" : "N",
                        file.isEncrypted ? "Y" : "N",
                        fileSize, file.filename);
                file.clearData(); // Optimization: Free memory
            }
        }

        int totalCapacityBytes = ctx.maxBits / 8;
        int remainingBits = ctx.maxBits - totalBitsUsed;
        int usedCapacityBytes = totalBitsUsed / 8;
        double percentageUsed = ctx.maxBits > 0 ? (double) totalBitsUsed / ctx.maxBits * 100 : 0.0;
        double percentageFree = ctx.maxBits > 0 ? (double) remainingBits / ctx.maxBits * 100 : 100.0;

        System.out.printf("\nTotal capacity: 100.00%%, %10d bytes, %11d bits%n", totalCapacityBytes, ctx.maxBits);
        System.out.printf("Used capacity : %6.2f%%, %10d bytes, %11d bits%n", percentageUsed, usedCapacityBytes, totalBitsUsed);
        System.out.printf("Free capacity : %6.2f%%, %10d bytes, %11d bits%n", percentageFree, remainingBits / 8, remainingBits);
    }

    /**
     * Handles bit manipulation for embedding and extracting data.
     */
    static class ImageProcessor {
        static void embedBits(BufferedImage image, int width, int height, byte[] data, boolean clearRemaining, int startBit, int bitsPerPixel) {
            int bitsPerChannel = bitsPerPixel / 3;
            int totalBits = data.length * 8;
            int currentBitPosition = 0;

            for (int y = 0; y < height && currentBitPosition < totalBits; y++) {
                for (int x = 0; x < width && currentBitPosition < totalBits; x++) {
                    int pixelIndex = y * width + x;
                    if (pixelIndex * bitsPerPixel < startBit) continue;

                    int rgb = image.getRGB(x, y);
                    int r = (rgb >> 16) & 0xFF;
                    int g = (rgb >> 8) & 0xFF;
                    int b = rgb & 0xFF;

                    for (int channel = 0; channel < 3 && currentBitPosition < totalBits; channel++) {
                        int byteIndex = currentBitPosition / 8;
                        int bitIndex = 7 - (currentBitPosition % 8);
                        int bit = (data[byteIndex] >> bitIndex) & 1;
                        if (channel == 0) {
                            r = bitsPerChannel == 2 ? (r & 0xFC) | (bit << 1) : (r & 0xFE) | bit;
                            if (bitsPerChannel == 2 && ++currentBitPosition < totalBits) {
                                byteIndex = currentBitPosition / 8;
                                bitIndex = 7 - (currentBitPosition % 8);
                                r |= (data[byteIndex] >> bitIndex) & 1;
                                currentBitPosition++;
                            } else {
                                currentBitPosition++;
                            }
                        } else if (channel == 1) {
                            g = bitsPerChannel == 2 ? (g & 0xFC) | (bit << 1) : (g & 0xFE) | bit;
                            if (bitsPerChannel == 2 && ++currentBitPosition < totalBits) {
                                byteIndex = currentBitPosition / 8;
                                bitIndex = 7 - (currentBitPosition % 8);
                                g |= (data[byteIndex] >> bitIndex) & 1;
                                currentBitPosition++;
                            } else {
                                currentBitPosition++;
                            }
                        } else {
                            b = bitsPerChannel == 2 ? (b & 0xFC) | (bit << 1) : (b & 0xFE) | bit;
                            if (bitsPerChannel == 2 && ++currentBitPosition < totalBits) {
                                byteIndex = currentBitPosition / 8;
                                bitIndex = 7 - (currentBitPosition % 8);
                                b |= (data[byteIndex] >> bitIndex) & 1;
                                currentBitPosition++;
                            } else {
                                currentBitPosition++;
                            }
                        }
                    }
                    image.setRGB(x, y, (r << 16) | (g << 8) | b);
                }
            }

            if (clearRemaining) {
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width; x++) {
                        int pixelIndex = y * width + x;
                        if (pixelIndex * bitsPerPixel < startBit + totalBits) continue;
                        int rgb = image.getRGB(x, y);
                        int r = bitsPerChannel == 2 ? (rgb >> 16) & 0xFC : (rgb >> 16) & 0xFE;
                        int g = bitsPerChannel == 2 ? (rgb >> 8) & 0xFC : (rgb >> 8) & 0xFE;
                        int b = bitsPerChannel == 2 ? rgb & 0xFC : rgb & 0xFE;
                        image.setRGB(x, y, (r << 16) | (g << 8) | b);
                    }
                }
            }
        }

        static int extractBit(BufferedImage image, int width, int currentBitPosition, byte[] target, int targetBit, int bitsPerPixel) {
            int bitsPerChannel = bitsPerPixel / 3;
            int pixelIndex = currentBitPosition / bitsPerPixel;
            if (pixelIndex >= image.getWidth() * image.getHeight()) {
                throw new IllegalStateException("Reached end of image at bit " + currentBitPosition);
            }

            int x = pixelIndex % width;
            int y = pixelIndex / width;
            int rgb = image.getRGB(x, y);
            int channelIndex = currentBitPosition % bitsPerPixel;
            int channel = channelIndex < bitsPerChannel ? (rgb >> 16) & 0xFF : channelIndex < 2 * bitsPerChannel ? (rgb >> 8) & 0xFF : rgb & 0xFF;
            int bitInChannel = bitsPerChannel == 2 ? (channelIndex % bitsPerChannel == 0 ? 1 : 0) : 0;

            target[targetBit / 8] |= ((channel >> bitInChannel) & 1) << (7 - (targetBit % 8));
            return currentBitPosition + 1;
        }
    }

    /**
     * Manages encryption, compression, and CRC calculations.
     */
    static class DataProcessor {
        private static final String AES_ALGORITHM = "AES";
        private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

        static byte[] encrypt(byte[] data, String password) throws Exception {
            SecretKeySpec key = generateKey(password);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(data);
            Arrays.fill(key.getEncoded(), (byte) 0);
            return encrypted;
        }

        static byte[] decrypt(byte[] data, String password) throws Exception {
            SecretKeySpec key = generateKey(password);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(data);
            Arrays.fill(key.getEncoded(), (byte) 0);
            return decrypted;
        }

        private static SecretKeySpec generateKey(String password) throws Exception {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), SALT, 100_000, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            byte[] key = skf.generateSecret(spec).getEncoded();
            SecretKeySpec secretKey = new SecretKeySpec(key, AES_ALGORITHM);
            Arrays.fill(key, (byte) 0);
            return secretKey;
        }

        static byte[] compress(byte[] data) throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length / 2);
            try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
                gzip.write(data);
            }
            return baos.toByteArray();
        }

        static byte[] decompress(byte[] data) throws IOException {
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length * 2);
            try (GZIPInputStream gzip = new GZIPInputStream(bais)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = gzip.read(buffer)) > 0) {
                    baos.write(buffer, 0, len);
                }
            }
            return baos.toByteArray();
        }

        static int calculateCRC(byte[] data) {
            CRC32 crc32 = new CRC32();
            crc32.update(data);
            return (int) crc32.getValue();
        }
    }

    /**
     * Utility methods for file and data handling.
     */
    static class Utils {
        static void validateImagePaths(String inputImagePath, String outputImagePath) {
            if (!inputImagePath.toLowerCase().endsWith(".png") || !outputImagePath.toLowerCase().endsWith(".png")) {
                throw new IllegalArgumentException("Input and output images must be PNG files.");
            }
            if (!inputImagePath.equals(outputImagePath) && new File(outputImagePath).exists()) {
                throw new IllegalStateException("Output file already exists: " + outputImagePath);
            }
        }

        static String getUniqueFilename(String outputDir, String originalFilename) {
            File file = new File(outputDir, originalFilename);
            if (!file.exists()) return originalFilename;

            String baseName = originalFilename.substring(0, originalFilename.lastIndexOf('.'));
            String extension = originalFilename.substring(originalFilename.lastIndexOf('.'));
            int suffix = 1;
            while (new File(outputDir, baseName + "-" + suffix + extension).exists()) {
                suffix++;
            }
            return baseName + "-" + suffix + extension;
        }

        static byte[] readFileToBytes(String filePath) throws IOException {
            File file = new File(filePath);
            byte[] data = new byte[(int) file.length()];
            try (FileInputStream fis = new FileInputStream(file)) {
                fis.read(data);
            }
            return data;
        }

        static byte[] intToBytes(int value) {
            return new byte[]{
                    (byte) (value >> 24),
                    (byte) (value >> 16),
                    (byte) (value >> 8),
                    (byte) value
            };
        }

        static int bytesToInt(byte[] bytes) {
            return ((bytes[0] & 0xFF) << 24) |
                   ((bytes[1] & 0xFF) << 16) |
                   ((bytes[2] & 0xFF) << 8) |
                   (bytes[3] & 0xFF);
        }
    }

    /**
     * Result of extracting files from an image.
     */
    static class ExtractResult {
        List<FileData> files;
        boolean magicFound;

        ExtractResult(List<FileData> files, boolean magicFound) {
            this.files = files;
            this.magicFound = magicFound;
        }
    }

    /**
     * Extracts embedded files from an image.
     */
    private static ExtractResult extractFilesFromImage(ImageContext ctx, SteganographyConfig config, boolean needData, boolean rawMode, boolean isListing, Integer targetFileNumber) throws Exception {
        List<FileData> files = new ArrayList<>();
        ByteArrayOutputStream baos = rawMode ? new ByteArrayOutputStream() : null;
        int currentBitPosition = 0;

        byte[] extractedMagic = new byte[4];
        currentBitPosition = extractBits(ctx, extractedMagic, currentBitPosition, 32);
        if (rawMode) baos.write(extractedMagic);

        if (!isValidMagic(extractedMagic)) {
            return new ExtractResult(files, false);
        }

        byte[] numFilesBytes = new byte[1];
        currentBitPosition = extractBits(ctx, numFilesBytes, currentBitPosition, 8);
        int numFiles = numFilesBytes[0] & 0xFF;
        if (rawMode) baos.write(numFiles);

        for (int fileIdx = 0; fileIdx < numFiles; fileIdx++) {
            try {
                byte[] filenameLengthBytes = new byte[1];
                currentBitPosition = extractBits(ctx, filenameLengthBytes, currentBitPosition, 8);
                int filenameLength = filenameLengthBytes[0] & 0xFF;
                if (filenameLength > MAX_FILENAME_LENGTH) {
                    throw new IllegalStateException("Invalid filename length at file " + (fileIdx + 1) + ": " + filenameLength);
                }

                byte[] filenameBytes = new byte[filenameLength];
                currentBitPosition = extractBits(ctx, filenameBytes, currentBitPosition, filenameLength * 8);
                String filename = new String(filenameBytes, StandardCharsets.UTF_8);

                byte[] statusFlagBytes = new byte[1];
                currentBitPosition = extractBits(ctx, statusFlagBytes, currentBitPosition, 8);
                int statusFlag = statusFlagBytes[0] & 0xFF;
                boolean isCompressed = (statusFlag & 0x01) != 0;
                boolean isEncrypted = (statusFlag & 0x02) != 0;

                byte[] crcBytes = new byte[4];
                currentBitPosition = extractBits(ctx, crcBytes, currentBitPosition, 32);
                int storedCrc = Utils.bytesToInt(crcBytes);

                byte[] lengthBytes = new byte[4];
                currentBitPosition = extractBits(ctx, lengthBytes, currentBitPosition, 32);
                int dataLength = Utils.bytesToInt(lengthBytes);

                byte[] data = new byte[dataLength];
                currentBitPosition = extractBits(ctx, data, currentBitPosition, dataLength * 8);

                if (rawMode) {
                    baos.write(filenameLengthBytes);
                    baos.write(filenameBytes);
                    baos.write(statusFlagBytes);
                    baos.write(crcBytes);
                    baos.write(lengthBytes);
                    baos.write(data);
                    continue;
                }

                byte[] embeddedData = Arrays.copyOf(data, data.length);
                byte[] processedData = needData ? Arrays.copyOf(data, data.length) : new byte[0];

                if (needData && isEncrypted) {
                    String password = config.passwords.get(fileIdx + 1);
                    if (password == null) password = config.passwords.get(0);
                    if (password == null) {
                        if ((isListing || targetFileNumber == null || targetFileNumber == 0 || targetFileNumber == fileIdx + 1) &&
                            !config.silentExtract && !config.silentDecrypt) {
                            System.err.println("Warning: File " + filename + " is encrypted, no password provided.");
                        }
                        processedData = new byte[0];
                    } else {
                        try {
                            processedData = DataProcessor.decrypt(processedData, password);
                        } catch (Exception e) {
                            if (isListing) {
                                if (!config.silentExtract && !config.silentDecrypt) {
                                    System.err.println("Warning: Decryption failed for file " + filename + ": " + e.getMessage());
                                }
                                processedData = new byte[0];
                            } else if (config.silentDecrypt) {
                                processedData = new byte[0];
                            } else if (config.skipCorrupted) {
                                if (!config.silentExtract) {
                                    System.err.println("Warning: Decryption failed for file " + filename + ".");
                                }
                                processedData = new byte[0];
                            } else {
                                throw new IllegalStateException("Decryption failed for file " + filename + ": " + e.getMessage());
                            }
                        }
                    }
                }

                if (needData && isCompressed && processedData.length > 0) {
                    try {
                        processedData = DataProcessor.decompress(processedData);
                    } catch (Exception e) {
                        if (isListing || config.skipCorrupted) {
                            if (!config.silentExtract && !config.silentDecrypt) {
                                System.err.println("Warning: Decompression failed for file " + filename + ".");
                            }
                            processedData = new byte[0];
                        } else {
                            throw new IllegalStateException("Decompression failed for file " + filename + ": " + e.getMessage());
                        }
                    }
                }

                files.add(new FileData(filename, processedData, storedCrc, isCompressed, isEncrypted, dataLength, embeddedData));
                Arrays.fill(data, (byte) 0);
            } catch (Exception e) {
                if (isListing || config.skipCorrupted) {
                    if (!config.silentExtract && !config.silentDecrypt) {
                        System.err.println("Warning: Failed to extract file " + (fileIdx + 1) + ": " + e.getMessage());
                    }
                    continue;
                }
                throw e;
            }
        }

        if (rawMode) {
            byte[] rawData = baos.toByteArray();
            files.add(new FileData("raw", rawData, 0, false, false, rawData.length, rawData));
        }
        return new ExtractResult(files, true);
    }

    private static int extractBits(ImageContext ctx, byte[] target, int startBit, int numBits) {
        int currentBitPosition = startBit;
        for (int i = 0; i < numBits; i++) {
            currentBitPosition = ImageProcessor.extractBit(ctx.image, ctx.width, currentBitPosition, target, i, ctx.bitsPerPixel);
        }
        return currentBitPosition;
    }

    private static byte[] buildDataToEmbed(List<FileData> files, SteganographyConfig config, boolean isNewFile) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] magicHeader = Arrays.copyOf(MAGIC_STEG, 4);
        magicHeader[3] |= (config.bitsPerPixel == 6 ? 1 : 0);
        baos.write(magicHeader);
        baos.write(files.size());

        for (FileData file : files) {
            byte[] rawData = file.data;
            byte[] processedData = file.embeddedData;
            boolean isCompressed = file.isCompressed;
            boolean isEncrypted = file.isEncrypted;

            if (isNewFile && !config.noCompressionFiles.contains(file.filename) && !isCompressed) {
                byte[] compressedData = DataProcessor.compress(rawData);
                if (compressedData.length < rawData.length) {
                    processedData = compressedData;
                    isCompressed = true;
                } else {
                    processedData = rawData;
                }
            } else if (isNewFile) {
                processedData = rawData;
            }

            if (isNewFile && isEncrypted) {
                processedData = DataProcessor.encrypt(processedData, config.passwords.get(0));
            }

            int crc = DataProcessor.calculateCRC(processedData);
            byte statusFlag = (byte) ((isCompressed ? 0x01 : 0) | (isEncrypted ? 0x02 : 0));
            byte[] filenameBytes = file.filename.getBytes(StandardCharsets.UTF_8);

            baos.write(filenameBytes.length);
            baos.write(filenameBytes);
            baos.write(statusFlag);
            baos.write(Utils.intToBytes(crc));
            baos.write(Utils.intToBytes(processedData.length));
            baos.write(processedData);

            file.embeddedSize = processedData.length;
            file.crc = crc;
            file.isCompressed = isCompressed;
            file.isEncrypted = isEncrypted;
            file.embeddedData = Arrays.copyOf(processedData, processedData.length);
            file.clearData(); // Optimization: Free raw data

            System.out.printf("Embedded file '%s': isCompressed=%b, isEncrypted=%b, size=%d, CRC=%08X%n",
                    file.filename, isCompressed, isEncrypted, processedData.length, crc);
        }

        return baos.toByteArray();
    }

    private static void appendDataToImage(ImageContext ctx, byte[] existingData, List<FileData> newFiles, SteganographyConfig config) throws Exception {
        byte[] newData = buildDataToEmbed(newFiles, config, true);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        if (existingData.length == 0) {
            baos.write(newData);
        } else {
            byte[] magicHeader = Arrays.copyOf(MAGIC_STEG, 4);
            magicHeader[3] |= (ctx.bitsPerPixel == 6 ? 1 : 0);
            baos.write(magicHeader);
            baos.write((byte) ((existingData[4] & 0xFF) + newFiles.size()));
            baos.write(existingData, 5, existingData.length - 5);
            baos.write(newData, 5, newData.length - 5);
        }

        embedDataInImage(ctx, baos.toByteArray());
    }

    private static void rewriteImage(ImageContext ctx, String outputImagePath, List<FileData> files, SteganographyConfig config) throws Exception {
        config.bitsPerPixel = ctx.bitsPerPixel;
        byte[] fullData = buildDataToEmbed(files, config, false);
        embedDataInImage(ctx, fullData);
        if (!ImageIO.write(ctx.image, "png", new File(outputImagePath))) {
            throw new IOException("Failed to write image to " + outputImagePath);
        }
    }

    private static void embedDataInImage(ImageContext ctx, byte[] data) {
        int totalBits = data.length * 8;
        int requiredPixels = (totalBits + ctx.bitsPerPixel - 1) / ctx.bitsPerPixel;

        if (ctx.width * ctx.height < requiredPixels) {
            int minSide = (int) Math.ceil(Math.sqrt(requiredPixels));
            throw new IllegalArgumentException("Image too small. Needs at least " + minSide + "x" + minSide + " pixels.");
        }

        ImageProcessor.embedBits(ctx.image, ctx.width, ctx.height, data, true, 0, ctx.bitsPerPixel);
    }

    public static void embedData(String inputImagePath, String outputImagePath, String[] dataFilePaths, SteganographyConfig config) throws Exception {
        if (dataFilePaths.length == 0) {
            throw new IllegalArgumentException("No files provided to embed.");
        }

        Utils.validateImagePaths(inputImagePath, outputImagePath);
        ImageContext ctx = new ImageContext(inputImagePath);
        validateMagicHeader(ctx);

        List<FileData> newFiles = new ArrayList<>(dataFilePaths.length);
        for (String dataFilePath : dataFilePaths) {
            File file = new File(dataFilePath);
            if (file.length() > ctx.maxBits / 8) {
                throw new IllegalArgumentException("File too large to embed: " + file.getName());
            }
            String filename = file.getName();
            byte[] filenameBytes = filename.getBytes(StandardCharsets.UTF_8);
            if (filenameBytes.length > MAX_FILENAME_LENGTH) {
                throw new IllegalArgumentException("Filename too long: " + filename);
            }
            byte[] data = Utils.readFileToBytes(dataFilePath);
            newFiles.add(new FileData(filename, data, 0, false, config.passwords.containsKey(0), 0, new byte[0]));
        }

        SteganographyConfig rawConfig = new SteganographyConfig();
        rawConfig.skipCorrupted = true;
        rawConfig.bitsPerPixel = ctx.bitsPerPixel;
        ExtractResult extractResult = extractFilesFromImage(ctx, rawConfig, false, true, false, null);
        byte[] existingData = extractResult.files.isEmpty() ? new byte[0] : extractResult.files.get(0).data;

        appendDataToImage(ctx, existingData, newFiles, config);
        if (!ImageIO.write(ctx.image, "png", new File(outputImagePath))) {
            throw new IOException("Failed to write image to " + outputImagePath);
        }
    }

    public static void deleteData(String inputImagePath, String outputImagePath, int fileNumber) throws Exception {
        Utils.validateImagePaths(inputImagePath, outputImagePath);
        ImageContext ctx = new ImageContext(inputImagePath);
        validateMagicHeader(ctx);

        SteganographyConfig config = new SteganographyConfig();
        config.skipCorrupted = true;
        config.bitsPerPixel = ctx.bitsPerPixel;
        ExtractResult extractResult = extractFilesFromImage(ctx, config, false, false, false, null);
        List<FileData> files = extractResult.files;

        if (files.isEmpty()) {
            throw new IllegalStateException("No files embedded in the image.");
        }
        if (fileNumber < 1 || fileNumber > files.size()) {
            throw new IllegalArgumentException("Invalid file number: " + fileNumber + ". Must be between 1 and " + files.size() + ".");
        }

        String deletedFilename = files.get(fileNumber - 1).filename;
        files.remove(fileNumber - 1);

        rewriteImage(ctx, outputImagePath, files, config);
        System.out.println("Deleted file " + fileNumber + " (" + deletedFilename + "). New image saved to " + outputImagePath);
    }

    public static void extractData(String inputImagePath, String outputDir, Integer fileNumber, SteganographyConfig config) throws Exception {
        File dir = new File(outputDir);
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Failed to create directory: " + outputDir);
        }
        if (!dir.isDirectory()) {
            throw new IllegalStateException(outputDir + " is not a directory.");
        }

        ImageContext ctx = new ImageContext(inputImagePath);
        validateMagicHeader(ctx);

        config.skipCorrupted = true;
        config.silentDecrypt = false;
        config.bitsPerPixel = ctx.bitsPerPixel;
        ExtractResult extractResult = extractFilesFromImage(ctx, config, true, false, false, fileNumber);
        List<FileData> files = extractResult.files;

        if (files.isEmpty()) {
            throw new IllegalStateException("No files embedded in the image.");
        }

        boolean extractAll = fileNumber == null || fileNumber == 0;
        if (!extractAll && (fileNumber < 1 || fileNumber > files.size())) {
            throw new IllegalArgumentException("Invalid file number: " + fileNumber + ". Must be 0 (all) or between 1 and " + files.size() + ".");
        }

        if (extractAll) {
            for (FileData file : files) {
                if (file.data.length == 0) {
                    System.out.println("Skipped " + file.filename + " (encrypted or corrupted)");
                    continue;
                }
                String uniqueFilename = Utils.getUniqueFilename(outputDir, file.filename);
                try (FileOutputStream fos = new FileOutputStream(new File(outputDir, uniqueFilename))) {
                    fos.write(file.data);
                }
                System.out.println("Extracted " + uniqueFilename + " to " + outputDir);
                file.clearData();
            }
        } else {
            FileData file = files.get(fileNumber - 1);
            if (file.data.length == 0) {
                throw new IllegalStateException("Cannot extract " + file.filename + " (encrypted or corrupted)");
            }
            String uniqueFilename = Utils.getUniqueFilename(outputDir, file.filename);
            try (FileOutputStream fos = new FileOutputStream(new File(outputDir, uniqueFilename))) {
                fos.write(file.data);
            }
            System.out.println("Extracted " + uniqueFilename + " to " + outputDir);
            file.clearData();
        }
    }

    private static void printHelp() {
        System.out.println("Usage: java Steganography [command] [options]");
        System.out.println("Commands:");
        System.out.println("  embed <input_image> <output_image> <data_file1> [<data_file2> ...] [--password <password>] [--no-compression <file1,file2,...>]");
        System.out.println("  extract <input_image> <output_dir> [file_number] [--password[N] <password>] [--skip-corrupted]");
        System.out.println("  list <input_image> [--password[N] <password>] [--skip-corrupted] [--noCRC]");
        System.out.println("  delete <input_image> <output_image> <file_number>");
        System.out.println("  format <input_image> [<output_image>] [--bits <1|2>]");
        System.out.println("  -h, --help");
        System.out.println("Options:");
        System.out.println("  --password[N] <password> - Encrypt/decrypt data for file N (or all if N is omitted).");
        System.out.println("  --no-compression <file1,file2,...> - Skip compression for specified files.");
        System.out.println("  --skip-corrupted - Skip corrupted files during extraction or listing.");
        System.out.println("  --noCRC - Suppress hexadecimal CRC values in the list command.");
        System.out.println("  --bits <1|2> - Set bits per pixel for format (1=3 bits, 2=6 bits; default 2).");
    }

    public static void main(String[] args) {
        try {
            if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help")) {
                printHelp();
                return;
            }

            SteganographyConfig config = new SteganographyConfig();
            List<String> mainArgs = new ArrayList<>();
            int i = 0;

            while (i < args.length) {
                if (args[i].startsWith("--password")) {
                    if (i + 1 >= args.length) throw new IllegalArgumentException(args[i] + " requires a value.");
                    String passwordArg = args[i].substring(10);
                    int fileNumber = passwordArg.isEmpty() ? 0 : Integer.parseInt(passwordArg);
                    if (fileNumber < 0) throw new IllegalArgumentException("Invalid file number in " + args[i]);
                    config.passwords.put(fileNumber, args[++i]);
                } else if (args[i].equals("--no-compression")) {
                    if (i + 1 >= args.length) throw new IllegalArgumentException("--no-compression requires a value.");
                    config.noCompressionFiles.addAll(Arrays.asList(args[++i].split(",")));
                } else if (args[i].equals("--skip-corrupted")) {
                    config.skipCorrupted = true;
                } else if (args[i].equals("--noCRC")) {
                    config.noCRC = true;
                } else if (args[i].equals("--bits")) {
                    if (i + 1 >= args.length) throw new IllegalArgumentException("--bits requires a value.");
                    int bitsOption = Integer.parseInt(args[++i]);
                    if (bitsOption != 1 && bitsOption != 2) {
                        throw new IllegalArgumentException("--bits must be 1 (3 bits per pixel) or 2 (6 bits per pixel).");
                    }
                    config.bitsPerPixel = bitsOption == 1 ? 3 : 6;
                } else {
                    mainArgs.add(args[i]);
                }
                i++;
            }

            if (mainArgs.isEmpty()) throw new IllegalArgumentException("No command provided.");
            String command = mainArgs.get(0).toLowerCase();

            switch (command) {
                case "embed":
                    if (mainArgs.size() < 4) throw new IllegalArgumentException("'embed' requires at least 3 arguments.");
                    if (config.passwords.size() > 1 || (config.passwords.size() == 1 && !config.passwords.containsKey(0))) {
                        throw new IllegalArgumentException("For embed, only --password is allowed.");
                    }
                    String[] dataFiles = mainArgs.subList(3, mainArgs.size()).toArray(new String[0]);
                    for (String noCompressFile : config.noCompressionFiles) {
                        if (Arrays.stream(dataFiles).noneMatch(f -> new File(f).getName().equals(noCompressFile.trim()))) {
                            throw new IllegalArgumentException("File in --no-compression not found: " + noCompressFile);
                        }
                    }
                    embedData(mainArgs.get(1), mainArgs.get(2), dataFiles, config);
                    break;
                case "extract":
                    if (mainArgs.size() != 3 && mainArgs.size() != 4) throw new IllegalArgumentException("'extract' requires 2 or 3 arguments.");
                    Integer fileNumber = mainArgs.size() == 4 ? Integer.parseInt(mainArgs.get(3)) : null;
                    extractData(mainArgs.get(1), mainArgs.get(2), fileNumber, config);
                    break;
                case "list":
                    if (mainArgs.size() != 2) throw new IllegalArgumentException("'list' requires 1 argument.");
                    listData(mainArgs.get(1), config);
                    break;
                case "delete":
                    if (mainArgs.size() != 4) throw new IllegalArgumentException("'delete' requires 3 arguments.");
                    deleteData(mainArgs.get(1), mainArgs.get(2), Integer.parseInt(mainArgs.get(3)));
                    break;
                case "format":
                    if (mainArgs.size() != 2 && mainArgs.size() != 3) throw new IllegalArgumentException("'format' requires 1 or 2 arguments.");
                    formatData(mainArgs.get(1), mainArgs.size() == 2 ? mainArgs.get(1) : mainArgs.get(2), config);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown command: " + command);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}
