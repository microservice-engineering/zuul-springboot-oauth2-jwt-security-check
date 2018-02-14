package com.vgc.zuul.preauth.security;

import com.google.common.base.MoreObjects;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.FileCopyUtils;

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

	@Bean
	protected byte[] parseJwtToken() {
		Resource resource = new ClassPathResource("public.cert");
		String publicKey = null;
		try {
			publicKey = new String(FileCopyUtils.copyToByteArray(resource.getInputStream()));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return publicKey.getBytes();
	}

	@Override
	public Object run() {

		// JWTVerifier jwtVerifier = null;
		// try {
		// jwtVerifier = JWT
		// .require(Algorithm.HMAC256("123456"))
		// .build();
		// } catch (IllegalArgumentException e1) {
		// // TODO Auto-generated catch block
		// e1.printStackTrace();
		// } catch (UnsupportedEncodingException e1) {
		// // TODO Auto-generated catch block
		// e1.printStackTrace();
		// }
		//
		RequestContext ctx = RequestContext.getCurrentContext();
		HttpServletRequest request = ctx.getRequest();
		try {
			String token = MoreObjects.firstNonNull(request.getHeader("Authorization"), "");
			// DecodedJWT decodedJWT = jwtVerifier.verify(token);
			// ctx.addZuulRequestHeader("jwt-payload", decodedJWT.getPayload());
			// ctx.addZuulRequestHeader("jwt-token", decodedJWT.getToken());
			// ctx.addZuulRequestHeader("jwt-header", decodedJWT.getHeader());
			try {

				Jws<Claims> clamins = Jwts.parser().setSigningKey(parseJwtToken()).parseClaimsJws(token);
				System.out.print("Claims is: " + clamins);
				// OK, we can trust this JWT

			} catch (SignatureException e) {
				System.out.print("Claims error");
				// don't trust the JWT!
			}
		} catch (Exception e) {
			logger.info("Failed request " + request.getRequestURI(), e);
			ctx.setSendZuulResponse(false);
			ctx.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
		}
		return null;
	}
}
