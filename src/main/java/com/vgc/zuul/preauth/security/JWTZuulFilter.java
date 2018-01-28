package com.vgc.zuul.preauth.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.base.MoreObjects;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class JWTZuulFilter extends ZuulFilter {

    Logger logger = LoggerFactory.getLogger(getClass());
    
    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 1;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() {
    	
    		JWTVerifier jwtVerifier = null;
			try {
				jwtVerifier = JWT
				     .require(Algorithm.HMAC256("123456"))
				     .build();
			} catch (IllegalArgumentException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (UnsupportedEncodingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        try {
            String token = MoreObjects.firstNonNull(request.getHeader("Authorization"), "");
            DecodedJWT decodedJWT = jwtVerifier.verify(token);
            ctx.addZuulRequestHeader("jwt-payload", decodedJWT.getPayload());
            ctx.addZuulRequestHeader("jwt-token", decodedJWT.getToken());
            ctx.addZuulRequestHeader("jwt-header", decodedJWT.getHeader());
        } catch (Exception e) {
            logger.info("Failed request " + request.getRequestURI(), e);
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
        }
        return null;
    }
}
