package com.zizo.scanner.resource;

import com.zizo.scanner.model.ScanResult;
import com.zizo.scanner.model.User;
import com.zizo.scanner.repository.ScanResultRepository;
import com.zizo.scanner.service.ScanService;
import io.quarkus.security.Authenticated;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import java.util.List;
import java.util.Map;

@Path("/scan")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ScanResource {

    @Inject
    ScanService scanService;

    @Inject
    ScanResultRepository scanResultRepository;

    public record ScanRequest(String url) {}

    @POST
    @PermitAll // scan public autorisé, comme aujourd'hui — passe à @Authenticated si tu veux le restreindre
    public Response scan(ScanRequest request, @Context SecurityContext ctx) {
        if (request == null || request.url() == null || request.url().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Le champ 'url' est requis."))
                    .build();
        }
        try {
            User owner = ctx.getUserPrincipal() != null
                    ? User.findByUsername(ctx.getUserPrincipal().getName())
                    : null;
            ScanResult result = scanService.scan(request.url(), owner);
            return Response.ok(result).build();
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_GATEWAY)
                    .entity(Map.of("error", "Impossible de scanner cette URL : " + e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/history")
    @Authenticated
    public List<ScanResult> history(@QueryParam("url") String url) {
        return scanResultRepository.lastNForUrl(url, 20);
    }
}
