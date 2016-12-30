package com.eventmanager.rest;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import com.eventmanager.dao.UserDao;
import com.eventmanager.model.User;
import com.eventmanager.security.Encrypt;
import com.eventmanager.security.JWTTokenNeeded;
import com.eventmanager.security.KeyGenerator;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@RequestScoped
@Path("/")
public class UserResource {
	
	@Inject
	private UserDao userDao;

	@Context
	private UriInfo uriInfo;

	//test purposes
	@GET
	@JWTTokenNeeded
	@Path("/sec")
	public String getSec()
	{
		return "Security";	
	}
	
	//test purposes
	@POST
	@Path("/log")
	public Response authenticateUser() {

		try{
			authenticate("username", "password");
			
			String token = getToken("username");
			NewCookie cookie = new NewCookie("token", "Bearer " + token);
			
			return Response.ok().cookie(cookie).build();
		}catch(Exception e){
			return Response.status(Response.Status.UNAUTHORIZED).build();
		}
	}
	
	@POST
	@Path("/login")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response authenticateUser(@FormParam("login") String login,
            @FormParam("password") String password) {

		try{
			authenticate(login, password);
			
			String token = getToken(login);
			NewCookie cookie = new NewCookie("token", "Bearer " + token);
			
			return Response.ok().cookie(cookie).build();
		}catch(Exception e){
			return Response.status(Response.Status.UNAUTHORIZED).build();
		}
	}
	
	@POST
	@Path("/logout")
	public Response logout(@CookieParam("token") javax.ws.rs.core.Cookie cookie){
		
		NewCookie jwtCookie = new NewCookie(cookie, null ,0 , false);
		
		return Response.ok().cookie(jwtCookie).build();
	}

	@POST
	@Path("/register")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response registerUser(User user) throws NoSuchAlgorithmException {

		byte[] salt = Encrypt.getSalt();
		user.setPassword(Encrypt.encryptSHA256(user.getPassword(), salt));
		user.setSalt(salt);

		userDao.addUser(user);

		return Response.status(Response.Status.OK).build();
	}

	private String getToken(String login) {

		Key key = KeyGenerator.generateKey();
		String jwtToken = Jwts.builder().setSubject(login)
				.setIssuer(uriInfo.getAbsolutePath().toString())
				.setIssuedAt(new Date())
				.signWith(SignatureAlgorithm.HS512, key).compact();
		return jwtToken;
	}
	
	private void authenticate(String login, String password){
		
		User findedUser = userDao.findByUserName(login);

		if (findedUser == null) {
			throw new SecurityException("Invalid user/password");
		}

		String pass = findedUser.getPassword();
		byte[] salt = findedUser.getSalt();

		if (!pass.equals(Encrypt.encryptSHA256(password, salt))) {
			throw new SecurityException("Invalid user/password");
		} 
	}
}
