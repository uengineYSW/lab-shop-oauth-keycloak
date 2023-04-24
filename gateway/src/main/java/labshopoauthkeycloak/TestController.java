package labshopoauthkeycloak;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    @RequestMapping(value="/permitAll", method = RequestMethod.GET)
    public ResponseEntity<String> permitAll() {
        return ResponseEntity.ok("OK! Everybody can access this resource.\n");
    }

    @RequestMapping(value="/authenticated", method = RequestMethod.GET)
    public ResponseEntity<String> authenticated() {
        return ResponseEntity.ok("OK! Authenticated Users can access this resource.\n");
    }

    @RequestMapping(value="/user")
    public ResponseEntity<String> userRoleOnly() {
        return ResponseEntity.ok("OK! Only Users with USER Role can access this resource.\n");
    }

    @RequestMapping(value="/admin")
    public ResponseEntity<String> adminRoleOnly() {
        return ResponseEntity.ok("OK! Only Users with ADMIN Role can access this resource.\n");
    }

    @RequestMapping(value="/abc")
    public ResponseEntity<String> abcRoleOnly() {
        return ResponseEntity.ok("OK! Only Users with abc Role can access this resource.\n");
    }

    @GetMapping("/token")
    public String getToken(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        return authorizedClient.getAccessToken().getTokenValue();
    }
}