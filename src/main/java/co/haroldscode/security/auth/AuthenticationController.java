package co.haroldscode.security.auth;

import co.haroldscode.security.auth.payload.request.LoginRequest;
import co.haroldscode.security.auth.payload.request.RegisterRequest;
import co.haroldscode.security.auth.payload.response.AuthenticationResponse;
import co.haroldscode.security.auth.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authService;

    @PostMapping("/sign-up")
    public ResponseEntity<AuthenticationResponse> signUp (
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authService.signUp(request));
    }

    @PostMapping("/sign-in")
    public ResponseEntity<AuthenticationResponse> signIn (
            @RequestBody LoginRequest request
    ) {
        return ResponseEntity.ok(authService.signIn(request));
    }
}
