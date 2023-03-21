package com.jerry;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@EnableJpaAuditing
@SpringBootApplication
public class TemplateJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(TemplateJwtApplication.class, args);
	}

}
