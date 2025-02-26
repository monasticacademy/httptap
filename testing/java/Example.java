import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;

public class Example {
    public static void main(String[] args) {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://example.com/"))
                .build();
        try {
            client.send(request, BodyHandlers.ofString());
        } catch (Exception ex) {
            System.out.println("error making http request: "+ ex.getMessage());
        }
    }
}
