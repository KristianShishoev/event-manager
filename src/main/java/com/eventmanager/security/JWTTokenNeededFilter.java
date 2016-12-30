package com.eventmanager.security;

import io.jsonwebtoken.Jwts;

import java.io.IOException;
import java.security.Key;
import java.util.Map;

import javax.annotation.Priority;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

@Provider
@JWTTokenNeeded
@Priority(Priorities.AUTHENTICATION)
public class JWTTokenNeededFilter implements ContainerRequestFilter {
	
	 @Override
	    public void filter(ContainerRequestContext requestContext) throws IOException {

	        Map<String, Cookie> cookies = requestContext.getCookies();
	        
	        if(cookies.size() < 1 || cookies.get("token") == null){
	        	throw new NotAuthorizedException("Authorization header must be provided");
	        }
	        
	        String jwt = cookies.get("token").getValue();

	        if (jwt == null || !jwt.startsWith("Bearer ")) {
	            throw new NotAuthorizedException("Authorization header must be provided");
	        }

	        String token = jwt.substring("Bearer".length()).trim();

	        try {

	        	Key key = KeyGenerator.generateKey();
	            Jwts.parser().setSigningKey(key).parseClaimsJws(token);
	        } catch (Exception e) {
	            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
	        }
	    }
}
