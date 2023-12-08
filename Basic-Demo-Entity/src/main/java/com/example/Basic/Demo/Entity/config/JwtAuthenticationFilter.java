package com.example.Basic.Demo.Entity.config;

import com.example.Security.User.Demo.dto.GenericResponse;
import com.example.Security.User.Demo.dto.TokenDto;
import com.example.Security.User.Demo.entity.AppUser;
import com.example.Security.User.Demo.repo.AppUserRepo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private JwtTokenUtils jwtTokenUtil;

    private AppUserRepo appUserRepo;

    JwtAuthenticationFilter(JwtTokenUtils jwtTokenUtil, AppUserRepo appUserRepo) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.appUserRepo = appUserRepo;
    }

    private static Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filter)
            throws ServletException, IOException {
        try {
            String authToken = req.getHeader("Authorization");
            //authTOken token get chestam
//            LoginDto loginDto=jwtTokenUtil.parseToken(authToken);
//
//            AppUser appUser=appUserRepo.findByEmail(loginDto.getEmail());
           // String user1=jwtTokenUtil.parseToken(authToken);
           // Map<String,String> username = jwtTokenUtil.parseToken(authToken);
            //AppUser user1=appUserRepo.findByEmail(user1);
      //  AppUser user = appUserRepo.findByEmail(appUser.getEmail());
          //  System.out.println(user.getEmail());
            TokenDto tokenDto=jwtTokenUtil.parseToken(authToken);
            AppUser appUser=appUserRepo.findByEmail(tokenDto.getEmail());
            if (appUser!=null) {
               // AppUser appUser=user.get();
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(appUser, null, Arrays.asList(
                        new SimpleGrantedAuthority(appUser.getRoleType().name())));
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                logger.info("authenticated user " + appUser.getEmail() + ", setting security context");
                SecurityContextHolder.getContext().setAuthentication(authentication);
                filter.doFilter(req, res);
            }

        } catch (Exception e) {
            e.printStackTrace();
            ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
            GenericResponse resp = new GenericResponse(HttpStatus.UNAUTHORIZED.value(), "UNAUTHORIZED");
            String jsonRespString = ow.writeValueAsString(resp);
            res.setContentType(MediaType.APPLICATION_JSON_VALUE);
            PrintWriter writer = res.getWriter();
            writer.write(jsonRespString);
            System.out.println("===============================");
        }
    }

}



