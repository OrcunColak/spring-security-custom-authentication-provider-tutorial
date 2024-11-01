package com.colak.springtutorial.authentication;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.Map;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;

    private final Map<String, String> userCredentials =
            Map.of("Sam", "{noop}password123",
                    "Jack", "{noop}password123"
            );

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        if (userCredentials.containsKey(username) && passwordEncoder.matches(password, userCredentials.get(username))) {
            UserDetails user = new User(username, password, Collections.emptyList());
            return new UsernamePasswordAuthenticationToken(user, password, Collections.emptyList());
        } else {
            throw new BadCredentialsException("Authentication failed for " + username);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
