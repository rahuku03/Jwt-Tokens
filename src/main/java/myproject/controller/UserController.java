package myproject.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import myproject.dto.AuthenticationToken;
import myproject.dto.UserAuthentication;
import myproject.dto.UserDataDTO;
import myproject.dto.UserResponseDTO;
import myproject.exception.CustomException;
import myproject.model.User;
import myproject.modelMapper.ObjectMapperUtils;
import myproject.service.UserService;

@RestController
@RequestMapping("/users")
@Api(tags = "users")
public class UserController {

  @Autowired
  private UserService userService;

  @Autowired
  private ModelMapper modelMapper;
  
  @Autowired
  private Environment env;

  @PostMapping(path="/signin",consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE},produces= {"application/json"})
  @ApiOperation(value = "${UserController.signin}")
  @ApiResponses(value = {//
      @ApiResponse(code = 400, message = "Something went wrong"), //
      @ApiResponse(code = 422, message = "Invalid username/password supplied")})
  
  public AuthenticationToken login(UserAuthentication user){
	
	  AuthenticationToken token=new AuthenticationToken();
	  token.setToken(userService.signin(user.getUsername(), user.getPassword()));
	  
	  return token;
   // return userService.signin(username, password);
  }

  @PostMapping("/signup")
  @ApiOperation(value = "${UserController.signup}")
  @ApiResponses(value = {//
      @ApiResponse(code = 400, message = "Something went wrong"), //
      @ApiResponse(code = 403, message = "Access denied"), //
      @ApiResponse(code = 422, message = "Username is already in use")})
  public AuthenticationToken signup(@ApiParam("Signup User") @RequestBody UserDataDTO user,HttpServletRequest req) {
	  
	  
	  String secret=env.getProperty("ClientId");
	  
	  System.out.println("CHECKING THE VALUE OF DATA "+secret);
	  String clientId="";
	
	  if(req.getParameter("clientId")==null) {
		  clientId="";
	  }else {
		  clientId=req.getParameter("clientId");
	  }
	
	 if(!clientId.equals(secret)) {
		throw new CustomException("You are not allowed to signup! Ask your adminsitrator", HttpStatus.UNPROCESSABLE_ENTITY);
	 }
	  
	 else {
		 
		 AuthenticationToken token=new AuthenticationToken();
		  token.setToken(userService.signup(modelMapper.map(user, User.class)));
         return token;
	 }
  }

  @DeleteMapping(value = "/{username}")
  @PreAuthorize("hasRole('ROLE_ADMIN')")
  @ApiOperation(value = "${UserController.delete}", authorizations = { @Authorization(value="apiKey") })
  @ApiResponses(value = {//
      @ApiResponse(code = 400, message = "Something went wrong"), //
      @ApiResponse(code = 403, message = "Access denied"), //
      @ApiResponse(code = 404, message = "The user doesn't exist"), //
      @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
  public String delete(@ApiParam("Username") @PathVariable String username) {
    userService.delete(username);
    return username;
  }

  
  
  
	
	  @GetMapping(value = "/all")
	  
	  @PreAuthorize("hasRole('ROLE_ADMIN')")
	  
	  @ApiOperation(value = "${UserController.all}", response =
	  UserResponseDTO.class,  responseContainer="List", authorizations = { @Authorization(value="apiKey") })
	  
	  @ApiResponses(value = {//
	  
	  @ApiResponse(code = 400, message = "Something went wrong"), //
	  
	  @ApiResponse(code = 403, message = "Access denied"), //
	  
	  @ApiResponse(code = 404, message = "The user doesn't exist"), //
	  
	  @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
	  public List<UserResponseDTO> searchAll() {
	 
		  
		 // return ObjectMapperUtils.mapAll(userService.searchAll(), UserResponseDTO.class);
	
		  
		return ObjectMapperUtils.mapAll(userService.searchAll(), UserResponseDTO.class);
	  }
	 

  
  @GetMapping(value = "/{username}")
  @PreAuthorize("hasRole('ROLE_ADMIN')")
  @ApiOperation(value = "${UserController.search}", response = UserResponseDTO.class, authorizations = { @Authorization(value="apiKey") })
  @ApiResponses(value = {//
      @ApiResponse(code = 400, message = "Something went wrong"), //
      @ApiResponse(code = 403, message = "Access denied"), //
      @ApiResponse(code = 404, message = "The user doesn't exist"), //
      @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
  public UserResponseDTO search(@ApiParam("Username") @PathVariable String username) {
    return modelMapper.map(userService.search(username), UserResponseDTO.class);
  }

  @GetMapping(value = "/me")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_CLIENT')")
  @ApiOperation(value = "${UserController.me}", response = UserResponseDTO.class, authorizations = { @Authorization(value="apiKey") })
  @ApiResponses(value = {//
      @ApiResponse(code = 400, message = "Something went wrong"), //
      @ApiResponse(code = 403, message = "Access denied"), //
      @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
  public UserResponseDTO whoami(HttpServletRequest req) {
    return modelMapper.map(userService.whoami(req), UserResponseDTO.class);
  }

  @GetMapping("/refresh")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_CLIENT')")
  public AuthenticationToken refresh(HttpServletRequest req) {
	  AuthenticationToken token=new AuthenticationToken();
	  token.setToken(userService.refresh(req.getRemoteUser()));
	  return token;
  }

}
