package mw.course.security.auth;

import lombok.RequiredArgsConstructor;
import mw.course.security.auth.model.AuthenticationRequest;
import mw.course.security.auth.model.AuthenticationResponse;
import mw.course.security.auth.model.RegisterRequest;
import mw.course.security.config.JwtService;
import mw.course.security.user.Role;
import mw.course.security.user.User;
import mw.course.security.user.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    //for Registration:
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    //for Authentication:
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        User user = User.builder()
                .firstname(request.getFirstName())
                .lastname(request.getLastName())
                .email(request.getEmail())
                .pass(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();


        Boolean isEmailExists = userRepository.checkUsernameEmailIfExists(user.getEmail());
        if(isEmailExists) throw new RuntimeException("Email already exists!");

        userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request.getPassword()
        ));

        //till that point we know that user is authenticated, so username (email) and password are correct
        //then we can generate a token:
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User has not been found!"));
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
