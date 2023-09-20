package co.haroldscode.security.auth.service;

import co.haroldscode.security.auth.payload.request.LoginRequest;
import co.haroldscode.security.auth.payload.request.RegisterRequest;
import co.haroldscode.security.auth.payload.response.AuthenticationResponse;
import co.haroldscode.security.config.JwtService;
import co.haroldscode.security.user.data.UserRepository;
import co.haroldscode.security.user.data.model.Role;
import co.haroldscode.security.user.data.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse signUp(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);

        var token = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }

    public AuthenticationResponse signIn(LoginRequest request) {
        /* Validate credential */
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        /* Credentials are ok ando continue with the logic */
        var user = userRepository.findUserByEmail(request.getEmail())
                .orElseThrow();

        var token = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }
}
