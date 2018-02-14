package com.vgc.zuul.preauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.ComponentScan;

@EnableZuulProxy
@SpringBootApplication
@ComponentScan
public class ZuulPreAuthenticationGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(ZuulPreAuthenticationGatewayApplication.class, args);
	}
}
