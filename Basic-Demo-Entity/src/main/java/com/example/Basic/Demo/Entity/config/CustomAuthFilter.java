package com.example.Basic.Demo.Entity.config;

import com.example.Security.User.Demo.dto.GenericResponse;
import com.example.Security.User.Demo.dto.LoginDto;
import com.example.Security.User.Demo.entity.AppUser;
import com.example.Security.User.Demo.repo.AppUserRepo;
import com.example.Security.User.Demo.service.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;


public class CustomAuthFilter extends OncePerRequestFilter {
    private UserService userService;
@Autowired
AppUserRepo appUserRepo;


BCryptPasswordEncoder bCryptPasswordEncoder=new BCryptPasswordEncoder();
    CustomAuthFilter(UserService userService) {
        this.userService = userService;
    }

    private static Logger logger = LoggerFactory.getLogger(CustomAuthFilter.class);

//    @Override
//    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filter)
//            throws IOException {
//        try {
//            String authToken = req.getHeader("Authorization");   //harini@gmail.com:harini1@
//            if (authToken != null) {                            //emial,password   --return loginDto
//                AppUser user = userService.verifyUser(generateLoginDto(authToken.split(":")[0], authToken.split(":")[1]));
//                System.out.println("AppUser === " + user.getEmail()+" "+user.getPassword());
//                if (user != null) {
//                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, Arrays.asList(
//                            new SimpleGrantedAuthority(user.getRoleType().name())));
//                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
//                    logger.info("authenticated user " + authToken.split(":")[0] + ", setting security context");
//                    SecurityContextHolder.getContext().setAuthentication(authentication);
//                    filter.doFilter(req, res);
//                } else {
//                    generateUnauthorisedAccess(res);
//                }
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//            generateUnauthorisedAccess(res);
//        }
//    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filter)
            throws IOException {
        try {
            String authToken = req.getHeader("Authorization");

            String email = authToken.split(":")[0];//header---dec     //cGF2YW5pQGdtYWlsLmNvbQ==email  cGF2YW5pMTIz
            String password = authToken.split(":")[1];
          System.out.println(email);
           AppUser userC = appUserRepo.findByEmail(email);
            System.out.println(userC.getEmail()+ " "+userC.getPassword());
            if (bCryptPasswordEncoder.matches(password, userC.getPassword())) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userC, null, Arrays.asList(
                        new SimpleGrantedAuthority(userC.getRoleType().name())));
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                logger.info("authenticated user " + email + ", setting security context");
                SecurityContextHolder.getContext().setAuthentication(authentication);
                filter.doFilter(req, res);
            }

        } catch (Exception e) {
            System.out.println(e);
            generateUnauthorisedAccess(res);
        }
    }

    public LoginDto generateLoginDto(String email, String password) {
        LoginDto dto = new LoginDto();
        dto.setEmail(email);
        dto.setPassword(password);
        return dto;
    }

    public void generateUnauthorisedAccess(HttpServletResponse res) throws JsonProcessingException, IOException {
        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        GenericResponse resp = new GenericResponse(HttpStatus.UNAUTHORIZED.value(), "UNAUTORISED");
        String jsonRespString = ow.writeValueAsString(resp);
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        PrintWriter writer = res.getWriter();
        writer.write(jsonRespString);
        System.out.println("===============================");
    }

}