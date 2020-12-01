package dto;

import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Server8081 {

    public static void main(String[] args) throws Exception{

        // Create a Server8081 at the port "8081"
        ServerSocket serverSocket = new ServerSocket(8081);

        while (true){
            // For listening
            final Socket socket = serverSocket.accept();

            new Thread(new Runnable() {
                public void run() {
                    try {
                        OutputStream outputStream = socket.getOutputStream();
                        // For Browser Parsing
                        outputStream.write("HTTP/1.1 200 OK\r\n".getBytes());

                        // Response Headers
                        // 1. Content-Type
                        outputStream.write("Content-Type:text/html\r\n".getBytes());
                        outputStream.write("Accept-Charset:utf-8\r\n".getBytes());
                        outputStream.write("Accept-Language:en-US\r\n".getBytes());
                        /*try {
                            Thread.sleep( 10000 );
                        } catch (Exception e){
                            // System.exit( 0 );
                        }*/
                        // Thread.sleep( 10000 );
                        outputStream.write("Cookie:Hacker\r\n".getBytes());

                        // For Browser Parsing
                        outputStream.write("\r\n".getBytes());

                        outputStream.write(("<html>\n" +
                                "<head></head>\n" +
                                "<body>\n" +
                                "<form action=\"http://cern.ch\" method=\"post\">\n" +
                                "  <input type=\"hidden\" name=\"testhiddden\" value=\"testvalue\">\n" +
                                "  <input type=\"submit\">\n" +
                                "</form>\n" +
                                "</body>\n" +
                                "</html>").getBytes());

                        socket.close();
                    }catch (Exception e){
                        e.printStackTrace();
                    }

                }
            }).start();
        }
    }
}
