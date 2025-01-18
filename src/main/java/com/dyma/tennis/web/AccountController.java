package com.dyma.tennis.web;

import com.dyma.tennis.model.UserAuthentication;
import com.dyma.tennis.model.UserCredentials;
import com.dyma.tennis.security.JwtService;
import com.nimbusds.jose.JOSEException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Accounts API")
@RestController
@RequestMapping("/accounts")
public class AccountController {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManagerBuilder authenticationManagerBuilder;

    @Operation(summary = "Authenticates user", description = "Authenticates user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User is logged in.",
                    content = {@Content(mediaType = "application/json",
                            schema = @Schema(implementation = UserCredentials.class))}),
            @ApiResponse(responseCode = "403", description = "User credentials are not valid."),
            @ApiResponse(responseCode = "400", description = "Login or password is not provided.")
    })
    @PostMapping("/login")
    public ResponseEntity<UserAuthentication> login(@RequestBody @Valid UserCredentials credentials) throws JOSEException {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(credentials.login(), credentials.password());
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        String jwt = jwtService.createToken(authentication);
        return new ResponseEntity<>(
                new UserAuthentication(authentication.getName(), jwt),
                HttpStatus.OK
        );
    }
}
