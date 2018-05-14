package br.ufu;

public class Conversions {

    public Conversions() {
    }

    public String ByteToBit(byte[] number) {
        int[] bits = new int[8 * number.length];

        for (int i = 0; i < number.length; i++) {
            int sourceByte = 0xFF & (int) number[i];
            int mask = 0x80;

            for (int k = 0; k < 8; k++) {
                int maskResult = sourceByte & mask;
                if (maskResult > 0) {
                    bits[8 * i + k] = 1;
                } else {
                    bits[8 * i + k] = 0;
                }

                mask = mask >> 1;
            }
        }

        return bits.toString();
    }
}
