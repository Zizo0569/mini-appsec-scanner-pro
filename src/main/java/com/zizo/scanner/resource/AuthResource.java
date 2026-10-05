package com.zizo.scanner.resource;

import com.zizo.scanner.model.User;
import com.zizo.scanner.service.AuthService;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.Map;

@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {

    @Inject
    AuthService authService;

    public record Credentials(String username, String password) {}

    @POST
    @Path("/register")
    @PermitAll
    public Response register(Credentials creds) {
        try {
            User user = authService.register(creds.username(), creds.password());
            return Response.status(Response.Status.CREATED)
                    .entity(Map.of("username", user.username))
                    .build();
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error", e.getMessage()))
                    .build();
        }
    }

    @POST
    @Path("/login")
    @PermitAll
    public Response login(Credentials creds) {
        try {
            String token = authService.login(creds.username(), creds.password());
            return Response.ok(Map.of("token", token)).build();
        } catch (SecurityException e) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", e.getMessage()))
                    .build();
        }
    }
}
