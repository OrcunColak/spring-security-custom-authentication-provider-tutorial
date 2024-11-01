package com.colak.springtutorial.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class DemoController {

    // http://localhost:8080/api/v1/secured/hello-world
    @GetMapping(value = "/secured/hello-world")
    public String securedCall() {
        return "hello world secured!!";
    }


}
