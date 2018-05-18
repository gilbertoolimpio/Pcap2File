package br.ufu.csv;

import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CsvFile {

    private static final char DEFAULT_SEPARATOR = ';';

    public static void writeLine(Writer w, List<String> values) throws IOException {
        writeLine(w, values, DEFAULT_SEPARATOR, ' ');
    }

    public static void writeLine(Writer w, List<String> values, char separators) throws IOException {
        writeLine(w, values, separators, ' ');
    }


    private static String followCVSformat(String value) {

        String result = value;
        if (result.contains("\"")) {
            result = result.replace("\"", "\"\"");
        }
        return result;

    }


    public static void writeLine(Writer w, List<String> values, char separators, char customQuote) throws IOException {

        boolean first = true;

        if (separators == ' ') {
            separators = DEFAULT_SEPARATOR;
        }

        StringBuilder sb = new StringBuilder();
        for (String value : values) {
            if (!first) {
                sb.append(separators);
            }
            if (customQuote == ' ') {
                sb.append(followCVSformat(value));
            } else {
                sb.append(customQuote).append(followCVSformat(value)).append(customQuote);
            }

            first = false;
        }
        sb.append("\n");
        w.append(sb.toString());
    }

    @SuppressWarnings("deprecation")
    public static void updateCSV(String fileToUpdate, String replace,
                                 int row, int col) throws IOException {

        File inputFile = new File(fileToUpdate);

        CSVReader reader = new CSVReader(new FileReader(inputFile), ',');
        List<String[]> csvBody = reader.readAll();
        csvBody.get(row)[col] = replace;
        reader.close();

        CSVWriter writer = new CSVWriter(new FileWriter(inputFile), ',');
        writer.writeAll(csvBody);
        writer.flush();
        writer.close();
    }

    @SuppressWarnings("deprecation")
    public static void insertNewId(String fileToUpdate) {
        File file = new File(fileToUpdate);

        try {
            CSVReader reader = new CSVReader(new FileReader(file), ',');
            List<String[]> csvBody = reader.readAll();
            List<List<String>> newArray = new ArrayList<>();
            reader.close();

            for (int i = 0; i < csvBody.size(); i++) {

                csvBody.get(i)[0] = csvBody.get(i)[1] + "-" + csvBody.get(i)[2] + "-" + csvBody.get(i)[3] + "-" + csvBody.get(i)[4];
                newArray.add(i, new ArrayList(Arrays.asList(csvBody.get(i).clone())));

                if (i == 0) {
                    newArray.get(i).add(csvBody.get(i).length, "PackageID");
                } else {
                    newArray.get(i).add(csvBody.get(i).length, String.valueOf(i));
                }

                csvBody.set(i, newArray.get(i).toArray(new String[newArray.size()]));
            }

            CSVWriter writer = new CSVWriter(new FileWriter(file), ',');
            writer.writeAll(csvBody);
            writer.flush();
            writer.close();
            
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
