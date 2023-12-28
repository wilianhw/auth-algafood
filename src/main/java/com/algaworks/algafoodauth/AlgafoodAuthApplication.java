package com.algaworks.algafoodauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AlgafoodAuthApplication {

    public static void main(String[] args) {
        SpringApplication springApplication = new SpringApplication(AlgafoodAuthApplication.class);
        springApplication.addListeners(new Base64ProtocalResolver());
        springApplication.run(args);
    }

}
