package com.example.Basic.Demo.Entity.config;

import com.example.Security.User.Demo.dto.TokenDto;
import com.example.Security.User.Demo.entity.AppUser;
import com.example.Security.User.Demo.enumpack.RoleType;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;

@Service
public class JwtTokenUtils {

    public static String secretKey = "841D8A6C80CBA4FCAD32D5367C18C53B";

    /**
     *
     */
    private static final long serialVersionUID = -1029281748694725202L;

    public String getToken(AppUser user) throws JOSEException {

        //Payload
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();
        claims.expirationTime(new Date(new Date().getTime() + 8 * 24 * 60 * 60 * 1000));
        claims.claim("email", user.getEmail()).claim("name",user.getName()).claim("role",user.getRoleType())
                .build();

        Payload payload = new Payload(claims.build().toJSONObject());

        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);

        DirectEncrypter encrypter = new DirectEncrypter(secretKey.getBytes(StandardCharsets.UTF_8));
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(encrypter);
        String token = jweObject.serialize();

        return token;
    }

    //final SignedJWT signedJWT = SignedJWT.parse(jwtToken);
//    public LoginDto parseToken(String token) throws BadJOSEException, ParseException, JOSEException {
//        ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<SimpleSecurityContext>();
//        JWKSource<SimpleSecurityContext> jweKeySource = new ImmutableSecret<SimpleSecurityContext>(secretKey.getBytes());
//        JWEKeySelector<SimpleSecurityContext> jweKeySelector =
//                new JWEDecryptionKeySelector<SimpleSecurityContext>(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256, jweKeySource);
//
//        jwtProcessor.setJWEKeySelector(jweKeySelector);
//
//        JWTClaimsSet claims = jwtProcessor.process(token, null);
//        //String email = (String) claims.getClaim("email");
////        return email;
////        Map<String,String> stringMap=new HashMap<>();
//////
////        //Iterator iterator=
////        stringMap.put("email",(String) claims.getClaim("email"));
////        stringMap.put("name",(String) claims.getClaim("name"));
////        return stringMap;
//        LoginDto appUser= (LoginDto) claims.getClaim("user");
//        return appUser;
//    }


    public TokenDto parseToken(String token) throws BadJOSEException, ParseException, JOSEException {
        ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<SimpleSecurityContext>();
        JWKSource<SimpleSecurityContext> jweKeySource = new ImmutableSecret<SimpleSecurityContext>(secretKey.getBytes());
        JWEKeySelector<SimpleSecurityContext> jweKeySelector =
                new JWEDecryptionKeySelector<SimpleSecurityContext>(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256, jweKeySource);  //based on algorithm decode tje tokn

        jwtProcessor.setJWEKeySelector(jweKeySelector);

        JWTClaimsSet claims = jwtProcessor.process(token, null);
        TokenDto tokenDto=new TokenDto();
        tokenDto.setName((String) claims.getClaim("name"));
        tokenDto.setEmail((String) claims.getClaim("email"));
        tokenDto.setRoleType(RoleType.valueOf((String) claims.getClaim("role")));

//        Map<String,String> stringMap=new HashMap<>();
////        String email = (String) claims.getClaim("email");
////        return email;
//        //Iterator iterator=
//        stringMap.put("email",(String) claims.getClaim("email"));
//        stringMap.put("name",(String) claims.getClaim("name"));
//        return stringMap;
        return tokenDto;
    }
}
