package mw.course.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService; // to manipulate with token
    private final UserDetailsService userDetailsService;

    // chain of responsibilities design pattern
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        //check the token:
        final String authHeader = request.getHeader("Authorization");
        final String tokenBeginning = "Bearer ";
        final String jwt;
        final String userNameEmail;
        if(authHeader == null || !authHeader.startsWith(tokenBeginning)){
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(tokenBeginning.length());
        userNameEmail = jwtService.extractUsername(jwt); //to extract user email from JWT token

        //if user has not been authenticated yet in the SecurityContextHolder,
            // then we need to use one from database and update SecurityContextHolder:
        if(userNameEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            //UserDetails userDetails or User userDetails = , because our User extends UserDetails object
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userNameEmail);
            if(jwtService.isTokenValid(jwt, userDetails)){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        //with no credentials (null)
                        userDetails, null, userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
