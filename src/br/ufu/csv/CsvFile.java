package br.ufu.csv;

import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;
import lombok.Getter;
import lombok.Setter;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class CsvFile {

    private static final char DEFAULT_SEPARATOR = ';';
    @Getter @Setter
    private static int flowCount = 0;

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

    @Deprecated
    public static void updateCsv(String fileUpdate, char separator, int line, int column, String newValue){

        try {
            Reader reader = Files.newBufferedReader(Paths.get(fileUpdate));
            CSVReader csvReader = new CSVReader(reader, separator);

            Writer writer = Files.newBufferedWriter(Paths.get(fileUpdate));



        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    @Deprecated
    public static void insertNewId(String fileToUpdate) {
        String[] line;
        String[] newLine;
        String newFile;
        boolean firstLine = true;
        int count = 0;
        try {
            newFile = fileToUpdate.replace(".csv", "_NEW.csv");
            Reader reader = Files.newBufferedReader(Paths.get(fileToUpdate));
            CSVWriter csvWriter = new CSVWriter(new FileWriter(newFile));
            CSVReader csvReader = new CSVReader(reader);

            while ((line = csvReader.readNext()) != null) {

                newLine = new String[line.length + 2];

                if (firstLine) {

                    System.arraycopy(line, 0, newLine, 0, line.length);
                    newLine[line.length] = line[1].trim() + "-" + line[2].trim() + "-" + line[3].trim() + "-" + line[4].trim();
                    newLine[line.length + 1] = "flowUniqueId";

                    csvWriter.writeNext(newLine);
                    firstLine = false;
                    count++;
                    continue;
                }

                System.arraycopy(line, 0, newLine, 0, line.length);
                newLine[line.length] = line[1] + "-" + line[2] + "-" + line[3] + "-" + line[4];
                newLine[line.length + 1] = String.valueOf(count);
                csvWriter.writeNext(newLine);

                count++;
                csvWriter.flush();

            }
            setFlowCount(count);
            reader.close();
            csvWriter.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
