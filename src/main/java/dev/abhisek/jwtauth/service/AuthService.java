package dev.abhisek.jwtauth.service;

import dev.abhisek.jwtauth.config.JwtService;
import dev.abhisek.jwtauth.model.AuthenticationRequest;
import dev.abhisek.jwtauth.model.AuthenticationResponse;
import dev.abhisek.jwtauth.model.RegisterRequest;
import dev.abhisek.jwtauth.repository.UserRepository;
import dev.abhisek.jwtauth.user.Role;
import dev.abhisek.jwtauth.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository repo;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        System.out.println(user);
        repo.save(user);
        var jwt = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwt)
                .build();
    }

    public AuthenticationResponse authorize(AuthenticationRequest request) {
        System.out.println(request);
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
        } catch (BadCredentialsException | DisabledException | LockedException e) {
            System.out.println(e.getMessage());
            System.out.println("Cause : " + e.getCause());
            e.printStackTrace();

        }
        var user = repo.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found!"));
        System.out.println(user);
        var jwt = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwt)
                .build();
    }
}
